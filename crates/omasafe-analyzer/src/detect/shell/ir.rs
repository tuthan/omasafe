//! Bounded typed structure for one shell logical unit.
//!
//! This is the first Stage B layer from `docs/detect-rs-maintenance-plan.md`.
//! The existing detector families still consume lexer tokens, but the tokens
//! now have one typed structural owner at the shell boundary. Compound groups
//! remain nodes of their own instead of being mistaken for ordinary argv.

use super::budget::MAX_SHELL_ANALYSIS_DEPTH;
use super::command::{
    ScriptCommand, command_arguments, command_basename, env_split_string_command,
    is_env_assignment, is_redirect_operator, segment_commands, skip_command_prefixes,
    skip_wrapper_options, statement_outcomes,
};
pub(in crate::detect) use super::lexer::WordProvenance;
use super::lexer::{ShellToken, SubstKind};
use super::syntax::{
    GroupKind, Outcomes, matching_group_close, pipeline_negated, pipeline_segments,
};

/// The list operator that controls whether a statement may run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum Guard {
    /// The first statement in a list has no preceding operator.
    Unconditional,
    /// A statement following `;`.
    Sequence,
    /// A statement following `&&`.
    And,
    /// A statement following `||`.
    Or,
    /// A statement following `&`.
    Background,
}

impl Guard {
    fn from_operator(operator: Option<&str>) -> Self {
        match operator {
            None => Self::Unconditional,
            Some(";") => Self::Sequence,
            Some("&&") => Self::And,
            Some("||") => Self::Or,
            Some("&") => Self::Background,
            // `conditional_statements` only emits the operators above. Keep
            // malformed/future input represented as an unconditional path.
            Some(_) => Self::Unconditional,
        }
    }
}

/// A word's best-known runtime value and how that value was produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct Word {
    pub(in crate::detect) value: String,
    pub(in crate::detect) provenance: WordProvenance,
    /// Child shell programs owned by command/process substitutions in this
    /// word. Arithmetic expansions keep no shell child because their words
    /// are expressions, not command positions.
    pub(in crate::detect) substitutions: Vec<ExecutedSubstitution>,
}

/// A command or process substitution that executes shell text while the
/// containing word is expanded. The optional program is absent only when the
/// shared nesting ceiling prevents another parse; the source remains
/// available to the bounded compatibility fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct ExecutedSubstitution {
    pub(in crate::detect) kind: SubstKind,
    pub(in crate::detect) source: String,
    pub(in crate::detect) program: Option<Box<ShellProgram>>,
}

/// One redirection at the command node's own nesting depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct Redirect {
    pub(in crate::detect) operator: String,
    pub(in crate::detect) target: Option<Word>,
}

/// A wrapper invocation retained around the command it launches. Keeping
/// wrappers typed avoids losing the command-position distinction when the IR
/// replaces the current token walks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct CommandWrapper {
    pub(in crate::detect) head: String,
    pub(in crate::detect) args: Vec<Word>,
}

/// A simple command after command-position and wrapper analysis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct Command {
    pub(in crate::detect) head: String,
    pub(in crate::detect) args: Vec<Word>,
    pub(in crate::detect) redirects: Vec<Redirect>,
    pub(in crate::detect) wrappers: Vec<CommandWrapper>,
    /// Shell text executed by a static `-c`/`eval` invocation. Keeping the
    /// parsed child beside its source lets detector layers share one parse.
    pub(in crate::detect) body: Option<ExecutedBody>,
}

/// A statically known shell body and its bounded child program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct ExecutedBody {
    pub(in crate::detect) source: String,
    pub(in crate::detect) program: Option<Box<ShellProgram>>,
}

/// Reachability of a statement or branch under the shell's known status
/// information. Maybe remains executable in the conservative analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum Reachability {
    Always,
    Never,
    Maybe,
}

impl Reachability {
    pub(in crate::detect) const fn is_reachable(self) -> bool {
        !matches!(self, Self::Never)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum WhileOrUntil {
    While,
    Until,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct Branch {
    pub(in crate::detect) condition: Vec<Statement>,
    pub(in crate::detect) body: Vec<Statement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct CaseBranch {
    pub(in crate::detect) patterns: Vec<Word>,
    pub(in crate::detect) body: Vec<Statement>,
}

/// A command node in a pipeline. Compound commands are explicit so their
/// bodies cannot be flattened into the surrounding command's argv.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) enum CommandNode {
    Simple(Command),
    Subshell {
        body: Vec<Statement>,
        redirects: Vec<Redirect>,
    },
    BraceGroup {
        body: Vec<Statement>,
        redirects: Vec<Redirect>,
    },
    Arithmetic {
        expression: Vec<Word>,
        redirects: Vec<Redirect>,
    },
    If {
        condition: Vec<Statement>,
        then_body: Vec<Statement>,
        elif_branches: Vec<Branch>,
        else_body: Vec<Statement>,
        redirects: Vec<Redirect>,
    },
    Loop {
        kind: WhileOrUntil,
        condition: Vec<Statement>,
        body: Vec<Statement>,
        redirects: Vec<Redirect>,
    },
    For {
        variable: Word,
        words: Vec<Word>,
        body: Vec<Statement>,
        redirects: Vec<Redirect>,
    },
    Case {
        word: Word,
        branches: Vec<CaseBranch>,
        redirects: Vec<Redirect>,
    },
    /// Unmatched or otherwise unsupported command-position syntax is kept as
    /// data rather than being guessed into a runnable command.
    Opaque {
        words: Vec<Word>,
        redirects: Vec<Redirect>,
    },
}

/// One pipeline and its command nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct Pipeline {
    pub(in crate::detect) negated: bool,
    pub(in crate::detect) commands: Vec<CommandNode>,
}

/// One conditional-list statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct Statement {
    pub(in crate::detect) guard: Guard,
    /// Whether at least one status path reaches this statement. Keeping this
    /// beside the typed guard lets detector walks skip statically dead
    /// branches without returning to raw control operators.
    pub(in crate::detect) reachable: Reachability,
    pub(in crate::detect) pipelines: Vec<Pipeline>,
}

/// A logical shell unit and its parsed token stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct LogicalUnit {
    pub(in crate::detect) start_line: u32,
    source: String,
    tokens: Vec<ShellToken>,
    pub(in crate::detect) statements: Vec<Statement>,
}

impl LogicalUnit {
    pub(in crate::detect) fn source(&self) -> &str {
        &self.source
    }

    pub(in crate::detect) fn tokens(&self) -> &[ShellToken] {
        &self.tokens
    }
}

/// Parsed shell logical units. Its size is bounded by the already bounded
/// source entry and the existing logical-unit/tokenization pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::detect) struct ShellProgram {
    pub(in crate::detect) units: Vec<LogicalUnit>,
}

impl ShellProgram {
    /// Parse the source units emitted by the shell source assembler.
    pub(in crate::detect) fn from_units(units: Vec<(u32, String)>) -> Self {
        Self {
            units: units
                .into_iter()
                .map(|(start_line, source)| parse_unit(start_line, source))
                .collect(),
        }
    }

    /// Parse child shell text through the same logical-unit and heredoc
    /// assembler used by top-level source. This keeps multiline `-c`, eval,
    /// and substitution programs from becoming one raw token unit.
    pub(in crate::detect) fn from_source(source: &str) -> Self {
        let units = super::source::shell_logical_units(
            source,
            &crate::detect::script::classify_heredoc_owner,
            &crate::detect::script::forwarded_body_fate,
        );
        Self::from_units(units)
    }

    pub(in crate::detect) fn units(&self) -> &[LogicalUnit] {
        &self.units
    }
}

fn parse_unit(start_line: u32, source: String) -> LogicalUnit {
    parse_unit_with_depth(start_line, source, 0)
}

fn parse_unit_with_depth(start_line: u32, source: String, depth: usize) -> LogicalUnit {
    let tokens = super::lexer::tokenize(&source);
    let statements = parse_statements(&tokens, depth);
    LogicalUnit {
        start_line,
        source,
        tokens,
        statements,
    }
}

fn child_program(source: &str, depth: usize) -> Option<Box<ShellProgram>> {
    (depth < MAX_SHELL_ANALYSIS_DEPTH as usize).then(|| Box::new(ShellProgram::from_source(source)))
}

fn parse_statements(tokens: &[ShellToken], depth: usize) -> Vec<Statement> {
    let mut outcomes = Outcomes::ANY;
    control_aware_statements(tokens)
        .into_iter()
        .filter(|(statement, _)| !statement.is_empty())
        .map(|(statement, guard)| {
            let reachable = statement_reachability(outcomes, guard);
            let commands = if parse_control_flow(statement, depth).is_some() {
                vec![parse_control_flow(statement, depth).expect("control flow just matched")]
            } else {
                pipeline_segments(statement)
                    .into_iter()
                    .filter(|segment| !segment.is_empty())
                    .map(|segment| parse_command_node(segment, depth))
                    .collect()
            };
            let parsed = Statement {
                guard: Guard::from_operator(guard),
                reachable,
                pipelines: if commands.is_empty() {
                    Vec::new()
                } else {
                    vec![Pipeline {
                        negated: pipeline_negated(statement),
                        commands,
                    }]
                },
            };
            outcomes = outcomes.advance(guard, statement_outcomes(statement));
            parsed
        })
        .collect()
}

fn parse_command_node(segment: &[ShellToken], depth: usize) -> CommandNode {
    if let Some((open, kind)) = compound_open(segment) {
        let Some(close) = matching_group_close(segment, open) else {
            return opaque_node(segment, depth);
        };
        if depth >= MAX_SHELL_ANALYSIS_DEPTH as usize {
            return opaque_node(segment, depth);
        }
        let redirects = redirects_at_depth_zero(segment, depth);
        return match kind {
            GroupKind::List if segment[open].operator() == Some("{") => CommandNode::BraceGroup {
                body: parse_statements(&segment[open + 1..close], depth + 1),
                redirects,
            },
            GroupKind::List => CommandNode::Subshell {
                body: parse_statements(&segment[open + 1..close], depth + 1),
                redirects,
            },
            GroupKind::Arithmetic => CommandNode::Arithmetic {
                expression: segment[open + 1..close]
                    .iter()
                    .filter_map(|token| word_from_token_at_depth(token, depth + 1))
                    .collect(),
                redirects,
            },
        };
    }

    if let Some(node) = parse_control_flow(segment, depth) {
        return node;
    }

    let commands = segment_commands(segment);
    let Some(last) = commands.last() else {
        return opaque_node(segment, depth);
    };
    let args = command_args(segment, last, depth).unwrap_or_else(|| {
        last.args
            .iter()
            .zip(last.arg_dynamic.iter().copied())
            .map(|(value, dynamic)| word_from_value(value, dynamic))
            .collect()
    });
    let wrappers = commands[..commands.len() - 1]
        .iter()
        .map(command_wrapper)
        .collect();
    let body = super::interpreter::static_command_body(last).map(|source| ExecutedBody {
        program: child_program(&source, depth + 1),
        source,
    });
    CommandNode::Simple(Command {
        head: last.head.to_owned(),
        args,
        redirects: redirects_at_depth_zero(segment, depth),
        wrappers,
        body,
    })
}

/// Find a compound opener after prefixes that belong to the surrounding
/// command (`VAR=1`, `!`, and leading redirects).
fn compound_open(segment: &[ShellToken]) -> Option<(usize, GroupKind)> {
    let mut index = 0usize;
    while let Some(token) = segment.get(index) {
        match token {
            ShellToken::Word { value, .. } if value == "!" || is_env_assignment(value) => {
                index += 1
            }
            ShellToken::Operator(operator) if is_redirect_operator(operator) => {
                index += 1;
                if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                    index += 1;
                }
            }
            ShellToken::Operator(operator) => {
                let kind = match operator.as_str() {
                    "(" | "{" => GroupKind::List,
                    "((" => GroupKind::Arithmetic,
                    _ => return None,
                };
                return Some((index, kind));
            }
            ShellToken::Word { .. } => return None,
        }
    }
    None
}

fn parse_control_flow(segment: &[ShellToken], depth: usize) -> Option<CommandNode> {
    let mut index = 0usize;
    skip_command_prefixes(segment, &mut index);
    match segment.get(index).and_then(ShellToken::word)? {
        "if" => parse_if(segment, index, depth),
        "while" => parse_loop(segment, index, depth, WhileOrUntil::While),
        "until" => parse_loop(segment, index, depth, WhileOrUntil::Until),
        "for" => parse_for(segment, index, depth),
        "case" => parse_case(segment, index, depth),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlBlock {
    If,
    Loop,
    Case,
}

fn statement_reachability(outcomes: Outcomes, guard: Option<&str>) -> Reachability {
    if !outcomes.executes(guard) {
        return Reachability::Never;
    }
    match guard {
        None | Some(";") | Some("&") => Reachability::Always,
        Some("&&") if outcomes.success && !outcomes.failure => Reachability::Always,
        Some("||") if outcomes.failure && !outcomes.success => Reachability::Always,
        Some("&&" | "||") => Reachability::Maybe,
        _ => Reachability::Maybe,
    }
}

/// Split a token list without treating the separators inside an `if`, loop,
/// or `case` block as top-level list boundaries. The ordinary splitter cannot
/// do this because shell control structures use `;` to separate their own
/// condition, body, and terminator clauses.
fn control_aware_statements(tokens: &[ShellToken]) -> Vec<(&[ShellToken], Option<&str>)> {
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut guard = None;
    let mut groups = 0i32;
    let mut controls = Vec::new();
    let mut command_start = true;

    for (index, token) in tokens.iter().enumerate() {
        match token {
            ShellToken::Operator(operator) => match operator.as_str() {
                "(" | "{" | "((" => {
                    groups += 1;
                    command_start = true;
                }
                ")" | "}" | "))" => {
                    groups = (groups - 1).max(0);
                    command_start = true;
                }
                ";" | "&&" | "||" | "&" if groups == 0 => {
                    if controls.is_empty() {
                        statements.push((&tokens[start..index], guard));
                        guard = Some(operator.as_str());
                        start = index + 1;
                    }
                    command_start = true;
                }
                "|" | "|&" => command_start = true,
                _ => {}
            },
            ShellToken::Word { value, .. } => {
                if groups == 0 && command_start {
                    match value.as_str() {
                        "if" => controls.push(ControlBlock::If),
                        "while" | "until" | "for" => controls.push(ControlBlock::Loop),
                        "case" => controls.push(ControlBlock::Case),
                        "fi" => pop_control(&mut controls, ControlBlock::If),
                        "done" => pop_control(&mut controls, ControlBlock::Loop),
                        "esac" => pop_control(&mut controls, ControlBlock::Case),
                        _ => {}
                    }
                }
                command_start = matches!(value.as_str(), "then" | "elif" | "else" | "do" | "in");
            }
        }
    }
    statements.push((&tokens[start..], guard));
    statements
}

fn pop_control(controls: &mut Vec<ControlBlock>, expected: ControlBlock) {
    if controls.last() == Some(&expected) {
        controls.pop();
    }
}

/// Find a control clause at the current block's level, skipping nested
/// control structures and grouped command lists.
fn control_marker_index(tokens: &[ShellToken], markers: &[&str], start: usize) -> Option<usize> {
    let mut groups = 0i32;
    let mut nested_controls = 0i32;
    let mut command_start = true;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            ShellToken::Operator(operator) => match operator.as_str() {
                "(" | "{" | "((" => {
                    groups += 1;
                    command_start = true;
                }
                ")" | "}" | "))" => {
                    groups = (groups - 1).max(0);
                    command_start = true;
                }
                ";" | "&&" | "||" | "&" | "|" | "|&" => command_start = true,
                _ => {}
            },
            ShellToken::Word { value, .. } => {
                if groups == 0 && command_start {
                    if nested_controls == 0 && markers.contains(&value.as_str()) {
                        return Some(index);
                    }
                    match value.as_str() {
                        "if" | "while" | "until" | "for" | "case" => nested_controls += 1,
                        "fi" | "done" | "esac" if nested_controls > 0 => nested_controls -= 1,
                        _ => {}
                    }
                }
                command_start = matches!(value.as_str(), "then" | "elif" | "else" | "do" | "in");
            }
        }
    }
    None
}

fn top_level_operator_index(
    tokens: &[ShellToken],
    operator_to_find: &str,
    start: usize,
) -> Option<usize> {
    let mut groups = 0i32;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            ShellToken::Operator(operator) if groups == 0 && operator == operator_to_find => {
                return Some(index);
            }
            ShellToken::Operator(operator) => match operator.as_str() {
                "(" | "{" | "((" => groups += 1,
                ")" | "}" | "))" => groups = (groups - 1).max(0),
                _ => {}
            },
            _ => {}
        }
    }
    None
}

fn apply_gate_reachability(body: &mut [Statement], reachability: Reachability) {
    for statement in body {
        statement.reachable = match (reachability, statement.reachable) {
            (Reachability::Never, _) | (_, Reachability::Never) => Reachability::Never,
            (Reachability::Always, current) => current,
            (Reachability::Maybe, Reachability::Always | Reachability::Maybe) => {
                Reachability::Maybe
            }
        };
    }
}

fn gate_with_condition(
    remaining: Reachability,
    condition: Reachability,
    take_success: bool,
) -> Reachability {
    match (remaining, condition, take_success) {
        (Reachability::Never, _, _) => Reachability::Never,
        (remaining, Reachability::Always, true) => remaining,
        (remaining, Reachability::Never, false) => remaining,
        (_, Reachability::Always, false) | (_, Reachability::Never, true) => Reachability::Never,
        (Reachability::Always | Reachability::Maybe, Reachability::Maybe, _) => Reachability::Maybe,
    }
}

fn condition_reachability(condition: &[Statement]) -> Reachability {
    if condition.is_empty() {
        return Reachability::Maybe;
    }
    if condition.iter().any(|statement| {
        statement
            .pipelines
            .iter()
            .flat_map(|pipeline| pipeline.commands.iter())
            .any(|node| matches!(node, CommandNode::Opaque { .. }))
    }) {
        return Reachability::Maybe;
    }
    let outcomes = condition
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
        .fold(Outcomes::ANY, |outcomes, statement| {
            let guard = match statement.guard {
                Guard::Unconditional => None,
                Guard::Sequence => Some(";"),
                Guard::And => Some("&&"),
                Guard::Or => Some("||"),
                Guard::Background => Some("&"),
            };
            outcomes.advance(guard, statements_outcomes(statement))
        });
    match (outcomes.success, outcomes.failure) {
        (true, false) => Reachability::Always,
        (false, true) => Reachability::Never,
        _ => Reachability::Maybe,
    }
}

fn statements_outcomes(statement: &Statement) -> Outcomes {
    statement
        .pipelines
        .iter()
        .flat_map(|pipeline| pipeline.commands.iter())
        .map(command_node_outcomes)
        .next()
        .unwrap_or(Outcomes::ANY)
}

fn command_node_outcomes(node: &CommandNode) -> Outcomes {
    match node {
        CommandNode::Simple(command) if command.head == "true" || command.head == ":" => Outcomes {
            success: true,
            failure: false,
        },
        CommandNode::Simple(command) if command.head == "false" => Outcomes {
            success: false,
            failure: true,
        },
        _ => Outcomes::ANY,
    }
}

fn parse_if(segment: &[ShellToken], start: usize, depth: usize) -> Option<CommandNode> {
    let then_index = control_marker_index(segment, &["then"], start + 1)?;
    let condition = parse_statements(&segment[start + 1..then_index], depth + 1);
    let fi_index = control_marker_index(segment, &["fi"], then_index + 1)?;
    let then_end = control_marker_index(segment, &["elif", "else", "fi"], then_index + 1)
        .filter(|index| *index < fi_index)
        .unwrap_or(fi_index);
    let mut then_body = parse_statements(&segment[then_index + 1..then_end], depth + 1);
    let condition_gate = condition_reachability(&condition);
    let mut remaining = gate_with_condition(Reachability::Always, condition_gate, true);
    apply_gate_reachability(&mut then_body, remaining);
    remaining = gate_with_condition(Reachability::Always, condition_gate, false);

    let mut elif_branches = Vec::new();
    let mut cursor = then_end;
    while cursor < fi_index {
        if segment[cursor].word() == Some("elif") {
            let branch_then = control_marker_index(segment, &["then"], cursor + 1)?;
            let branch_end =
                control_marker_index(segment, &["elif", "else", "fi"], branch_then + 1)
                    .filter(|index| *index < fi_index)
                    .unwrap_or(fi_index);
            let branch_condition = parse_statements(&segment[cursor + 1..branch_then], depth + 1);
            let mut body = parse_statements(&segment[branch_then + 1..branch_end], depth + 1);
            let branch_condition_reachability = condition_reachability(&branch_condition);
            let branch_gate = gate_with_condition(remaining, branch_condition_reachability, true);
            apply_gate_reachability(&mut body, branch_gate);
            remaining = gate_with_condition(remaining, branch_condition_reachability, false);
            elif_branches.push(Branch {
                condition: branch_condition,
                body,
            });
            cursor = branch_end;
        } else {
            break;
        }
    }
    let else_body = if cursor < fi_index && segment[cursor].word() == Some("else") {
        let mut body = parse_statements(&segment[cursor + 1..fi_index], depth + 1);
        apply_gate_reachability(&mut body, remaining);
        body
    } else {
        Vec::new()
    };
    Some(CommandNode::If {
        condition,
        then_body,
        elif_branches,
        else_body,
        redirects: redirects_at_depth_zero(segment, depth),
    })
}

fn parse_loop(
    segment: &[ShellToken],
    start: usize,
    depth: usize,
    kind: WhileOrUntil,
) -> Option<CommandNode> {
    let do_index = control_marker_index(segment, &["do"], start + 1)?;
    let done_index = control_marker_index(segment, &["done"], do_index + 1)?;
    let condition = parse_statements(&segment[start + 1..do_index], depth + 1);
    let mut body = parse_statements(&segment[do_index + 1..done_index], depth + 1);
    let condition_reachability = condition_reachability(&condition);
    let body_reachability = match (kind, condition_reachability) {
        (WhileOrUntil::While, Reachability::Never)
        | (WhileOrUntil::Until, Reachability::Always) => Reachability::Never,
        (_, reachability) => reachability,
    };
    for statement in &mut body {
        statement.reachable = match (body_reachability, statement.reachable) {
            (Reachability::Never, _) | (_, Reachability::Never) => Reachability::Never,
            (Reachability::Always, current) => current,
            (Reachability::Maybe, Reachability::Always | Reachability::Maybe) => {
                Reachability::Maybe
            }
        };
    }
    Some(CommandNode::Loop {
        kind,
        condition,
        body,
        redirects: redirects_at_depth_zero(segment, depth),
    })
}

fn parse_for(segment: &[ShellToken], start: usize, depth: usize) -> Option<CommandNode> {
    let variable = word_from_token_at_depth(segment.get(start + 1)?, depth)?;
    let do_index = control_marker_index(segment, &["do"], start + 2)?;
    let in_index = control_marker_index(segment, &["in"], start + 2);
    let words_start = in_index.map_or(start + 2, |index| index + 1);
    let words_end = do_index;
    let words = segment[words_start..words_end]
        .iter()
        .filter_map(|token| word_from_token_at_depth(token, depth))
        .collect();
    let done_index = control_marker_index(segment, &["done"], do_index + 1)?;
    let body = parse_statements(&segment[do_index + 1..done_index], depth + 1);
    Some(CommandNode::For {
        variable,
        words,
        body,
        redirects: redirects_at_depth_zero(segment, depth),
    })
}

fn parse_case(segment: &[ShellToken], start: usize, depth: usize) -> Option<CommandNode> {
    let in_index = control_marker_index(segment, &["in"], start + 1)?;
    let end = control_marker_index(segment, &["esac"], in_index + 1)?;
    let word = segment[start + 1..in_index]
        .iter()
        .find_map(|token| word_from_token_at_depth(token, depth))?;
    let mut branches = Vec::new();
    let mut cursor = in_index + 1;
    while cursor < end {
        let close = top_level_operator_index(segment, ")", cursor)?;
        if close > end {
            return None;
        }
        let patterns = segment[cursor..close]
            .iter()
            .filter_map(|token| word_from_token_at_depth(token, depth))
            .collect();
        let body_start = close + 1;
        let mut body_end = end;
        let mut terminator = None;
        let mut index = body_start;
        while index + 1 < end {
            if segment[index].operator() == Some(";") && segment[index + 1].operator() == Some(";")
            {
                body_end = index;
                terminator = Some(index + 2);
                break;
            }
            index += 1;
        }
        let body = parse_statements(&segment[body_start..body_end], depth + 1);
        branches.push(CaseBranch { patterns, body });
        cursor = terminator.unwrap_or(end);
    }
    Some(CommandNode::Case {
        word,
        branches,
        redirects: redirects_at_depth_zero(segment, depth),
    })
}

/// Collect redirects that belong to the command node itself. Redirects in a
/// nested compound body are left with that body's node.
fn redirects_at_depth_zero(segment: &[ShellToken], depth: usize) -> Vec<Redirect> {
    let mut redirects = Vec::new();
    let mut nesting = 0i32;
    let mut index = 0usize;
    while index < segment.len() {
        match &segment[index] {
            ShellToken::Operator(operator) => match operator.as_str() {
                "(" | "{" | "((" => nesting += 1,
                ")" | "}" | "))" => nesting = (nesting - 1).max(0),
                operator if nesting == 0 && is_redirect_operator(operator) => {
                    redirects.push(Redirect {
                        operator: operator.to_owned(),
                        target: segment
                            .get(index + 1)
                            .and_then(|token| word_from_token_at_depth(token, depth)),
                    });
                    index += 1; // the target is data, not another redirect
                }
                _ => {}
            },
            ShellToken::Word { .. } => {}
        }
        index += 1;
    }
    redirects
}

/// Recover the final command's actual token start so its arguments retain
/// full substitution provenance. Wrapper parsing remains delegated to the
/// existing command-position model during this compatibility slice.
fn command_start(segment: &[ShellToken]) -> Option<usize> {
    let mut index = 0usize;
    skip_command_prefixes(segment, &mut index);
    loop {
        let head = segment.get(index).and_then(ShellToken::word)?;
        let basename = command_basename(head);
        if !matches!(
            basename,
            "sudo" | "pkexec" | "doas" | "command" | "env" | "exec" | "time"
        ) {
            return Some(index);
        }
        index += 1;
        if basename == "env" && env_split_string_command(segment, index).is_some() {
            return None;
        }
        if !skip_wrapper_options(basename, segment, &mut index) {
            return None;
        }
    }
}

fn command_args(
    segment: &[ShellToken],
    command: &ScriptCommand<'_>,
    depth: usize,
) -> Option<Vec<Word>> {
    let start = command_start(segment)?;
    let arguments = command_arguments(segment, start + 1);
    if arguments.len() != command.args.len() {
        return None;
    }
    let mut args = Vec::with_capacity(arguments.len());
    let mut index = start + 1;
    while index < segment.len() {
        match &segment[index] {
            ShellToken::Operator(operator) if is_redirect_operator(operator) => {
                index += 1;
                if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                    index += 1;
                }
            }
            ShellToken::Word { .. } => {
                args.push(word_from_token_at_depth(&segment[index], depth).expect("word token"));
                index += 1;
            }
            ShellToken::Operator(_) => index += 1,
        }
    }
    Some(args)
}

fn command_wrapper(command: &ScriptCommand<'_>) -> CommandWrapper {
    CommandWrapper {
        head: command.head.to_owned(),
        args: command
            .args
            .iter()
            .zip(command.arg_dynamic.iter().copied())
            .map(|(value, dynamic)| word_from_value(value, dynamic))
            .collect(),
    }
}

fn opaque_node(segment: &[ShellToken], depth: usize) -> CommandNode {
    CommandNode::Opaque {
        words: segment
            .iter()
            .filter_map(|token| word_from_token_at_depth(token, depth))
            .collect(),
        redirects: redirects_at_depth_zero(segment, depth),
    }
}

fn word_from_token_at_depth(token: &ShellToken, depth: usize) -> Option<Word> {
    let ShellToken::Word {
        value,
        substitutions,
        provenance,
        ..
    } = token
    else {
        return None;
    };
    let substitutions = substitutions
        .iter()
        .map(|substitution| ExecutedSubstitution {
            kind: substitution.kind,
            source: substitution.inner.clone(),
            program: match substitution.kind {
                SubstKind::Command | SubstKind::Process => {
                    child_program(&substitution.inner, depth + 1)
                }
                SubstKind::Arithmetic => None,
            },
        })
        .collect();
    Some(Word {
        value: value.clone(),
        provenance: *provenance,
        substitutions,
    })
}

fn word_from_value(value: &str, dynamic: bool) -> Word {
    Word {
        value: value.to_owned(),
        provenance: if dynamic {
            WordProvenance::PARAMETER | WordProvenance::FIELD_SPLIT
        } else {
            WordProvenance::EMPTY
        },
        substitutions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Command, CommandNode, Guard, Reachability, ShellProgram, WhileOrUntil, Word, WordProvenance,
    };
    use crate::detect::shell::lexer::SubstKind;

    #[test]
    fn parses_guards_pipelines_and_compounds_without_flattening() {
        let program = ShellProgram::from_units(vec![(
            7,
            "false && curl https://example.test/x | sh; (echo safe; wget https://example.test/y)\n"
                .to_owned(),
        )]);
        let unit = &program.units()[0];
        assert_eq!(unit.start_line, 7);
        let statements: Vec<_> = unit
            .statements
            .iter()
            .filter(|statement| !statement.pipelines.is_empty())
            .collect();
        assert_eq!(statements.len(), 3);
        assert_eq!(statements[0].guard, Guard::Unconditional);
        assert_eq!(statements[0].pipelines[0].commands.len(), 1);
        assert_eq!(statements[1].guard, Guard::And);
        assert_eq!(statements[1].pipelines[0].commands.len(), 2);
        assert!(!statements[1].pipelines[0].negated);
        assert_eq!(statements[2].guard, Guard::Sequence);
        assert!(matches!(
            statements[2].pipelines[0].commands[0],
            CommandNode::Subshell { .. }
        ));
    }

    #[test]
    fn retains_word_provenance_and_redirect_targets() {
        let program = ShellProgram::from_units(vec![(
            1,
            "curl \"$(printf url)\" <(cat input) > output; echo $NAME\n".to_owned(),
        )]);
        let unit = &program.units()[0];
        let CommandNode::Simple(command) = &unit.statements[0].pipelines[0].commands[0] else {
            panic!("expected simple command");
        };
        assert_eq!(command.args[0].provenance, WordProvenance::COMMAND_SUBST);
        assert_eq!(command.args[1].provenance, WordProvenance::PROCESS_SUBST);
        assert_eq!(command.redirects[0].operator, ">");
        assert_eq!(
            command.redirects[0]
                .target
                .as_ref()
                .expect("redirect target")
                .value,
            "output"
        );
        let CommandNode::Simple(echo) = &unit.statements[1].pipelines[0].commands[0] else {
            panic!("expected simple command");
        };
        assert_eq!(
            echo.args[0].provenance,
            WordProvenance::PARAMETER | WordProvenance::FIELD_SPLIT
        );
    }

    #[test]
    fn collects_composable_provenance_causes_with_quote_context() {
        let program = ShellProgram::from_units(vec![(
            1,
            "printf '%s' ${name}$(cmd) \"$name\" \"*.sh\" *.sh ~/x {a,b} $((1+2))".to_owned(),
        )]);
        let CommandNode::Simple(command) =
            &program.units()[0].statements[0].pipelines[0].commands[0]
        else {
            panic!("expected simple command");
        };

        assert_eq!(
            command.args[1].provenance,
            WordProvenance::PARAMETER | WordProvenance::COMMAND_SUBST | WordProvenance::FIELD_SPLIT
        );
        assert_eq!(command.args[2].provenance, WordProvenance::PARAMETER);
        assert_eq!(command.args[3].provenance, WordProvenance::EMPTY);
        assert_eq!(command.args[4].provenance, WordProvenance::GLOB);
        assert_eq!(command.args[5].provenance, WordProvenance::TILDE);
        assert_eq!(command.args[6].provenance, WordProvenance::BRACE);
        assert_eq!(command.args[7].provenance, WordProvenance::ARITHMETIC);
    }

    #[test]
    fn owns_static_bodies_and_executed_substitution_programs() {
        let program = ShellProgram::from_units(vec![(
            1,
            "sh -c 'curl https://example.test/body | sh'; echo \"$(wget https://example.test/sub)\" <(curl https://example.test/process)"
                .to_owned(),
        )]);
        let unit = &program.units()[0];

        let CommandNode::Simple(interpreter) = &unit.statements[0].pipelines[0].commands[0] else {
            panic!("expected static-body command");
        };
        let body = interpreter.body.as_ref().expect("owned shell body");
        assert_eq!(body.source, "curl https://example.test/body | sh");
        let body_unit = &body.program.as_ref().expect("parsed child program").units()[0];
        assert_eq!(body_unit.statements[0].pipelines[0].commands.len(), 2);

        let CommandNode::Simple(echo) = &unit.statements[1].pipelines[0].commands[0] else {
            panic!("expected substitution command");
        };
        assert_eq!(echo.args.len(), 2);
        assert_eq!(echo.args[0].substitutions.len(), 1);
        assert_eq!(echo.args[0].substitutions[0].kind, SubstKind::Command);
        assert_eq!(
            echo.args[0].substitutions[0]
                .program
                .as_ref()
                .expect("command substitution program")
                .units()[0]
                .statements[0]
                .pipelines[0]
                .commands[0],
            CommandNode::Simple(Command {
                head: "wget".to_owned(),
                args: vec![Word {
                    value: "https://example.test/sub".to_owned(),
                    provenance: WordProvenance::EMPTY,
                    substitutions: Vec::new(),
                }],
                redirects: Vec::new(),
                wrappers: Vec::new(),
                body: None,
            })
        );
        assert_eq!(echo.args[1].substitutions.len(), 1);
        assert_eq!(echo.args[1].substitutions[0].kind, SubstKind::Process);
        assert!(echo.args[1].substitutions[0].program.is_some());
    }

    #[test]
    fn parses_structured_control_flow_and_reachability() {
        let program = ShellProgram::from_units(vec![
            (
                1,
                "if false; then curl https://example.test/dead; fi".to_owned(),
            ),
            (
                2,
                "for item in one; do wget https://example.test/dead; done".to_owned(),
            ),
            (
                3,
                "while false; do curl https://example.test/dead; done".to_owned(),
            ),
        ]);

        let first_unit = &program.units()[0];
        let CommandNode::If {
            condition,
            then_body,
            ..
        } = &first_unit.statements[0].pipelines[0].commands[0]
        else {
            panic!("expected structured if");
        };
        assert_eq!(
            condition[0].pipelines[0].commands[0],
            CommandNode::Simple(Command {
                head: "false".to_owned(),
                args: Vec::new(),
                redirects: Vec::new(),
                wrappers: Vec::new(),
                body: None,
            })
        );
        assert_eq!(then_body[0].reachable, Reachability::Never);

        let second_unit = &program.units()[1];
        let CommandNode::For {
            variable,
            words,
            body,
            ..
        } = &second_unit.statements[0].pipelines[0].commands[0]
        else {
            panic!("expected structured for");
        };
        assert_eq!(variable.value, "item");
        assert_eq!(words[0].value, "one");
        assert_eq!(body[0].reachable, Reachability::Always);

        let third_unit = &program.units()[2];
        let CommandNode::Loop { kind, body, .. } =
            &third_unit.statements[0].pipelines[0].commands[0]
        else {
            panic!("expected structured while");
        };
        assert_eq!(*kind, WhileOrUntil::While);
        assert_eq!(body[0].reachable, Reachability::Never);
    }

    #[test]
    fn child_programs_use_multiline_logical_and_heredoc_frontend() {
        let program = ShellProgram::from_source(
            "sh -c 'if false; then\n  curl https://example.test/dead\nfi'\n",
        );
        let CommandNode::Simple(command) =
            &program.units()[0].statements[0].pipelines[0].commands[0]
        else {
            panic!("expected child-owning interpreter");
        };
        let body = command.body.as_ref().expect("static child body");
        let child = body.program.as_ref().expect("parsed child program");
        let CommandNode::If { then_body, .. } =
            &child.units()[0].statements[0].pipelines[0].commands[0]
        else {
            panic!("expected structured child if");
        };
        assert_eq!(then_body[0].reachable, Reachability::Never);
    }

    #[test]
    fn malformed_and_unicode_shell_text_stays_bounded_and_typed() {
        for source in [
            "echo '🙂' | sh -c 'printf \"✓\"'; (",
            "$(unterminated \\\n+             echo \"é\"",
            "{ printf '\\xff'; } > /tmp/é",
        ] {
            let program = ShellProgram::from_units(vec![(1, source.to_owned())]);
            assert_eq!(program.units().len(), 1);
            assert!(!program.units()[0].statements.is_empty());
        }
    }
}
