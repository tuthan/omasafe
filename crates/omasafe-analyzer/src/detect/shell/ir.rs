//! Bounded typed structure for one shell logical unit.
//!
//! This is the first Stage B layer from `docs/detect-rs-maintenance-plan.md`.
//! Detector families consume this typed structure first; only opaque or
//! depth-capped children retain a bounded token fallback. Compound groups
//! remain nodes of their own instead of being mistaken for ordinary argv.

use std::sync::Arc;

use super::budget::{MAX_SHELL_PARSE_DEPTH, ShellParseBudget};
use super::command::{
    ScriptCommand, command_arguments, command_basename, env_split_string_command,
    is_redirect_operator, segment_commands, skip_command_prefixes, skip_wrapper_options,
    statement_outcomes,
};
pub(in crate::detect) use super::lexer::WordProvenance;
use super::lexer::{ShellToken, SubstKind};
use super::syntax::{
    ControlScanner, GroupKind, Outcomes, matching_group_close, pipeline_negated, pipeline_segments,
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
    pub(in crate::detect) program: Option<Arc<ShellProgram>>,
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
    pub(in crate::detect) head_substitutions: Vec<ExecutedSubstitution>,
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
    pub(in crate::detect) program: Option<Arc<ShellProgram>>,
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
    parse_budget_exhausted: bool,
}

impl LogicalUnit {
    pub(in crate::detect) fn source(&self) -> &str {
        &self.source
    }

    pub(in crate::detect) fn tokens(&self) -> &[ShellToken] {
        &self.tokens
    }

    /// Whether this unit contains an opaque or depth-capped child that needs
    /// the bounded token fallback.
    pub(in crate::detect) fn requires_legacy_fallback(&self) -> bool {
        self.parse_budget_exhausted || statements_require_legacy_fallback(&self.statements)
    }
}

/// Parsed shell logical units. Its size is bounded by the already bounded
/// source entry and the existing logical-unit/tokenization pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::detect) struct ShellProgram {
    pub(in crate::detect) units: Vec<LogicalUnit>,
    parse_budget_exhausted: bool,
}

impl ShellProgram {
    /// Parse the source units emitted by the shell source assembler.
    pub(in crate::detect) fn from_units(units: Vec<(u32, String)>) -> Self {
        let mut budget = ShellParseBudget::new();
        Self::from_units_at_depth(units, 0, &mut budget)
    }

    fn from_units_at_depth(
        units: Vec<(u32, String)>,
        depth: usize,
        budget: &mut ShellParseBudget,
    ) -> Self {
        let parsed_units = units
            .into_iter()
            .map(|(start_line, source)| parse_unit_with_depth(start_line, source, depth, budget))
            .collect();
        Self {
            units: parsed_units,
            parse_budget_exhausted: budget.exhausted(),
        }
    }

    /// Parse shell text through the same logical-unit and heredoc assembler
    /// used by top-level source, preserving the caller's recursion depth.
    pub(in crate::detect) fn from_source(source: &str, depth: usize) -> Self {
        let mut budget = ShellParseBudget::new();
        Self::from_source_with_budget(source, depth, &mut budget)
    }

    fn from_source_with_budget(source: &str, depth: usize, budget: &mut ShellParseBudget) -> Self {
        let units = super::source::shell_logical_units(
            source,
            &crate::detect::script::classify_heredoc_owner,
            &crate::detect::script::forwarded_body_fate,
        );
        Self::from_units_at_depth(units, depth, budget)
    }

    pub(in crate::detect) fn units(&self) -> &[LogicalUnit] {
        &self.units
    }

    /// Whether any node in this program is incomplete enough that a bounded
    /// token fallback is still required. Complete programs are consumed only
    /// through the typed IR; callers use this bit to keep opaque/depth-capped
    /// syntax conservative and disclose the resulting coverage limitation.
    pub(in crate::detect) fn requires_legacy_fallback(&self) -> bool {
        self.parse_budget_exhausted || self.units.iter().any(LogicalUnit::requires_legacy_fallback)
    }
}

fn statements_require_legacy_fallback(statements: &[Statement]) -> bool {
    statements.iter().any(|statement| {
        statement
            .pipelines
            .iter()
            .any(|pipeline| pipeline.commands.iter().any(node_requires_legacy_fallback))
    })
}

fn node_requires_legacy_fallback(node: &CommandNode) -> bool {
    if node_redirects(node)
        .iter()
        .filter_map(|redirect| redirect.target.as_ref())
        .any(word_requires_legacy_fallback)
    {
        return true;
    }
    match node {
        CommandNode::Simple(command) => {
            command.body.as_ref().is_some_and(|body| {
                body.program.is_none()
                    || body
                        .program
                        .as_deref()
                        .is_some_and(ShellProgram::requires_legacy_fallback)
            }) || command.args.iter().any(word_requires_legacy_fallback)
                || command
                    .head_substitutions
                    .iter()
                    .any(substitution_requires_legacy_fallback)
                || command
                    .wrappers
                    .iter()
                    .any(|wrapper| wrapper.args.iter().any(word_requires_legacy_fallback))
        }
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            statements_require_legacy_fallback(body)
        }
        CommandNode::Arithmetic { expression, .. } => {
            expression.iter().any(word_requires_legacy_fallback)
        }
        CommandNode::If {
            condition,
            then_body,
            elif_branches,
            else_body,
            ..
        } => {
            statements_require_legacy_fallback(condition)
                || statements_require_legacy_fallback(then_body)
                || elif_branches.iter().any(|branch| {
                    statements_require_legacy_fallback(&branch.condition)
                        || statements_require_legacy_fallback(&branch.body)
                })
                || statements_require_legacy_fallback(else_body)
        }
        CommandNode::Loop {
            condition, body, ..
        } => {
            statements_require_legacy_fallback(condition)
                || statements_require_legacy_fallback(body)
        }
        CommandNode::For {
            variable,
            words,
            body,
            ..
        } => {
            word_requires_legacy_fallback(variable)
                || words.iter().any(word_requires_legacy_fallback)
                || statements_require_legacy_fallback(body)
        }
        CommandNode::Case { word, branches, .. } => {
            word_requires_legacy_fallback(word)
                || branches.iter().any(|branch| {
                    branch.patterns.iter().any(word_requires_legacy_fallback)
                        || statements_require_legacy_fallback(&branch.body)
                })
        }
        CommandNode::Opaque { .. } => true,
    }
}

fn node_redirects(node: &CommandNode) -> &[Redirect] {
    match node {
        CommandNode::Simple(command) => &command.redirects,
        CommandNode::Subshell { redirects, .. }
        | CommandNode::BraceGroup { redirects, .. }
        | CommandNode::Arithmetic { redirects, .. }
        | CommandNode::If { redirects, .. }
        | CommandNode::Loop { redirects, .. }
        | CommandNode::For { redirects, .. }
        | CommandNode::Case { redirects, .. }
        | CommandNode::Opaque { redirects, .. } => redirects,
    }
}

fn word_requires_legacy_fallback(word: &Word) -> bool {
    word.substitutions
        .iter()
        .any(substitution_requires_legacy_fallback)
}

fn substitution_requires_legacy_fallback(substitution: &ExecutedSubstitution) -> bool {
    (matches!(substitution.kind, SubstKind::Command | SubstKind::Process)
        && substitution.program.is_none())
        || substitution
            .program
            .as_deref()
            .is_some_and(ShellProgram::requires_legacy_fallback)
}

fn parse_unit_with_depth(
    start_line: u32,
    source: String,
    depth: usize,
    budget: &mut ShellParseBudget,
) -> LogicalUnit {
    let tokens = super::lexer::tokenize(&source);
    let statements = if budget.spend_node() {
        parse_statements(&tokens, depth, budget)
    } else {
        vec![opaque_statement()]
    };
    LogicalUnit {
        start_line,
        source,
        tokens,
        statements,
        parse_budget_exhausted: budget.exhausted(),
    }
}

fn child_program(
    source: &str,
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Option<Arc<ShellProgram>> {
    if depth >= MAX_SHELL_PARSE_DEPTH || !budget.reserve_child(source.len()) {
        return None;
    }
    Some(Arc::new(ShellProgram::from_source_with_budget(
        source, depth, budget,
    )))
}

fn parse_statements(
    tokens: &[ShellToken],
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Vec<Statement> {
    let mut outcomes = Outcomes::ANY;
    let mut parsed_statements = Vec::new();
    for (statement, guard) in control_aware_statements(tokens)
        .into_iter()
        .filter(|(statement, _)| !statement.is_empty())
    {
        if !budget.spend_node() {
            parsed_statements.push(opaque_statement());
            break;
        }
        let reachable = statement_reachability(outcomes, guard);
        let commands: Vec<CommandNode> = pipeline_segments(statement)
            .into_iter()
            .filter(|segment| !segment.is_empty())
            .map(|segment| parse_command_node(segment, depth, budget))
            .collect();
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
        parsed_statements.push(parsed);
    }
    parsed_statements
}

fn opaque_statement() -> Statement {
    Statement {
        guard: Guard::Unconditional,
        reachable: Reachability::Maybe,
        pipelines: vec![Pipeline {
            negated: false,
            commands: vec![CommandNode::Opaque {
                words: Vec::new(),
                redirects: Vec::new(),
            }],
        }],
    }
}

fn parse_command_node(
    segment: &[ShellToken],
    depth: usize,
    budget: &mut ShellParseBudget,
) -> CommandNode {
    if !budget.spend_node() {
        return opaque_node();
    }
    if let Some((open, kind)) = compound_open(segment) {
        let Some(close) = matching_group_close(segment, open) else {
            return opaque_node();
        };
        if depth >= MAX_SHELL_PARSE_DEPTH {
            return opaque_node();
        }
        let redirects = redirects_at_depth_zero(segment, depth, budget);
        return match kind {
            GroupKind::List if segment[open].operator() == Some("{") => CommandNode::BraceGroup {
                body: parse_statements(&segment[open + 1..close], depth + 1, budget),
                redirects,
            },
            GroupKind::List => CommandNode::Subshell {
                body: parse_statements(&segment[open + 1..close], depth + 1, budget),
                redirects,
            },
            GroupKind::Arithmetic => CommandNode::Arithmetic {
                expression: segment[open + 1..close]
                    .iter()
                    .filter_map(|token| word_from_token_at_depth(token, depth + 1, budget))
                    .collect(),
                redirects,
            },
        };
    }

    if depth < MAX_SHELL_PARSE_DEPTH
        && let Some(node) = parse_control_flow(segment, depth, budget)
    {
        return node;
    }

    let commands = segment_commands(segment);
    let Some(last) = commands.last() else {
        return opaque_node();
    };
    let args = command_args(segment, last, depth, budget).unwrap_or_else(|| {
        last.args
            .iter()
            .zip(last.arg_dynamic.iter().copied())
            .map(|(value, dynamic)| word_from_value(value, dynamic))
            .collect()
    });
    let head_substitutions = command_start(segment)
        .and_then(|start| word_from_token_at_depth(segment.get(start)?, depth, budget))
        .map(|word| word.substitutions)
        .unwrap_or_default();
    let wrappers = commands[..commands.len() - 1]
        .iter()
        .map(command_wrapper)
        .collect();
    let body = super::interpreter::static_command_body(last).map(|source| ExecutedBody {
        program: child_program(&source, depth + 1, budget),
        source,
    });
    CommandNode::Simple(Command {
        head: last.head.to_owned(),
        head_substitutions,
        args,
        redirects: redirects_at_depth_zero(segment, depth, budget),
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
            ShellToken::Word { .. }
                if token.syntax_word() == Some("!") || token.assignment_word().is_some() =>
            {
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

fn parse_control_flow(
    segment: &[ShellToken],
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Option<CommandNode> {
    let mut index = 0usize;
    skip_command_prefixes(segment, &mut index);
    match segment.get(index).and_then(ShellToken::syntax_word)? {
        "if" => parse_if(segment, index, depth, budget),
        "while" => parse_loop(segment, index, depth, WhileOrUntil::While, budget),
        "until" => parse_loop(segment, index, depth, WhileOrUntil::Until, budget),
        "for" => parse_for(segment, index, depth, budget),
        "case" => parse_case(segment, index, depth, budget),
        _ => None,
    }
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
    let mut scanner = ControlScanner::new();

    for (index, token) in tokens.iter().enumerate() {
        scanner.prepare(token);
        if let Some(operator) = token.operator()
            && matches!(operator, ";" | "&&" | "||" | "&")
            && scanner.can_split()
        {
            statements.push((&tokens[start..index], guard));
            guard = Some(operator);
            start = index + 1;
        }
        scanner.step(token);
    }
    statements.push((&tokens[start..], guard));
    statements
}

/// Find a control clause at the current block's level, skipping nested
/// control structures and grouped command lists.
fn control_marker_index(tokens: &[ShellToken], markers: &[&str], start: usize) -> Option<usize> {
    let mut scanner = ControlScanner::new();
    for token in tokens.iter().take(start) {
        scanner.prepare(token);
        scanner.step(token);
    }
    let base_depth = scanner.control_depth();
    for (index, token) in tokens.iter().enumerate().skip(start) {
        scanner.prepare(token);
        if scanner.marker_at(token, tokens.get(index + 1), markers, base_depth) {
            return Some(index);
        }
        scanner.step(token);
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
    let Some(pipeline) = statement.pipelines.first() else {
        return Outcomes::ANY;
    };
    let mut outcomes = pipeline
        .commands
        .last()
        .map(command_node_outcomes)
        .unwrap_or(Outcomes::ANY);
    if pipeline.negated {
        std::mem::swap(&mut outcomes.success, &mut outcomes.failure);
    }
    outcomes
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

fn parse_if(
    segment: &[ShellToken],
    start: usize,
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Option<CommandNode> {
    let then_index = control_marker_index(segment, &["then"], start + 1)?;
    let condition = parse_statements(&segment[start + 1..then_index], depth + 1, budget);
    let fi_index = control_marker_index(segment, &["fi"], then_index + 1)?;
    let then_end = control_marker_index(segment, &["elif", "else", "fi"], then_index + 1)
        .filter(|index| *index < fi_index)
        .unwrap_or(fi_index);
    let mut then_body = parse_statements(&segment[then_index + 1..then_end], depth + 1, budget);
    let condition_gate = condition_reachability(&condition);
    let mut remaining = gate_with_condition(Reachability::Always, condition_gate, true);
    apply_gate_reachability(&mut then_body, remaining);
    remaining = gate_with_condition(Reachability::Always, condition_gate, false);

    let mut elif_branches = Vec::new();
    let mut cursor = then_end;
    while cursor < fi_index {
        if segment[cursor].syntax_word() == Some("elif") {
            let branch_then = control_marker_index(segment, &["then"], cursor + 1)?;
            let branch_end =
                control_marker_index(segment, &["elif", "else", "fi"], branch_then + 1)
                    .filter(|index| *index < fi_index)
                    .unwrap_or(fi_index);
            let mut branch_condition =
                parse_statements(&segment[cursor + 1..branch_then], depth + 1, budget);
            let mut body =
                parse_statements(&segment[branch_then + 1..branch_end], depth + 1, budget);
            let branch_condition_reachability = condition_reachability(&branch_condition);
            apply_gate_reachability(&mut branch_condition, remaining);
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
    let else_body = if cursor < fi_index && segment[cursor].syntax_word() == Some("else") {
        let mut body = parse_statements(&segment[cursor + 1..fi_index], depth + 1, budget);
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
        redirects: redirects_around_control(segment, depth, start, fi_index, budget),
    })
}

fn parse_loop(
    segment: &[ShellToken],
    start: usize,
    depth: usize,
    kind: WhileOrUntil,
    budget: &mut ShellParseBudget,
) -> Option<CommandNode> {
    let do_index = control_marker_index(segment, &["do"], start + 1)?;
    let done_index = control_marker_index(segment, &["done"], do_index + 1)?;
    let condition = parse_statements(&segment[start + 1..do_index], depth + 1, budget);
    let mut body = parse_statements(&segment[do_index + 1..done_index], depth + 1, budget);
    let condition_reachability = condition_reachability(&condition);
    let body_reachability = match (kind, condition_reachability) {
        (WhileOrUntil::While, Reachability::Never)
        | (WhileOrUntil::Until, Reachability::Always) => Reachability::Never,
        (WhileOrUntil::While, Reachability::Always)
        | (WhileOrUntil::Until, Reachability::Never) => Reachability::Always,
        (_, Reachability::Maybe) => Reachability::Maybe,
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
        redirects: redirects_around_control(segment, depth, start, done_index, budget),
    })
}

fn parse_for(
    segment: &[ShellToken],
    start: usize,
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Option<CommandNode> {
    let variable = word_from_token_at_depth(segment.get(start + 1)?, depth, budget)?;
    let do_index = control_marker_index(segment, &["do"], start + 2)?;
    let in_index = control_marker_index(segment, &["in"], start + 2);
    let words_start = in_index.map_or(start + 2, |index| index + 1);
    let words_end = do_index;
    let words: Vec<Word> = segment[words_start..words_end]
        .iter()
        .filter_map(|token| word_from_token_at_depth(token, depth, budget))
        .collect();
    let done_index = control_marker_index(segment, &["done"], do_index + 1)?;
    let mut body = parse_statements(&segment[do_index + 1..done_index], depth + 1, budget);
    let body_reachability = if in_index.is_none() {
        Reachability::Maybe
    } else if words.is_empty() {
        Reachability::Never
    } else {
        Reachability::Always
    };
    apply_gate_reachability(&mut body, body_reachability);
    Some(CommandNode::For {
        variable,
        words,
        body,
        redirects: redirects_around_control(segment, depth, start, done_index, budget),
    })
}

fn parse_case(
    segment: &[ShellToken],
    start: usize,
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Option<CommandNode> {
    let in_index = control_marker_index(segment, &["in"], start + 1)?;
    let end = control_marker_index(segment, &["esac"], in_index + 1)?;
    let word = segment[start + 1..in_index]
        .iter()
        .find_map(|token| word_from_token_at_depth(token, depth, budget))?;
    let mut branches = Vec::new();
    let mut cursor = in_index + 1;
    while cursor < end {
        while cursor < end && segment[cursor].operator() == Some(";") {
            cursor += 1;
        }
        if cursor >= end {
            break;
        }
        let close = top_level_operator_index(segment, ")", cursor)?;
        if close > end {
            return None;
        }
        let patterns = segment[cursor..close]
            .iter()
            .filter_map(|token| word_from_token_at_depth(token, depth, budget))
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
        let body = parse_statements(&segment[body_start..body_end], depth + 1, budget);
        branches.push(CaseBranch { patterns, body });
        cursor = terminator.unwrap_or(end);
    }
    Some(CommandNode::Case {
        word,
        branches,
        redirects: redirects_around_control(segment, depth, start, end, budget),
    })
}

/// Collect redirects that belong to the command node itself. Redirects in a
/// nested compound body are left with that body's node.
fn redirects_at_depth_zero(
    segment: &[ShellToken],
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Vec<Redirect> {
    let mut redirects = Vec::new();
    let mut nesting = 0i32;
    let mut index = 0usize;
    while index < segment.len() {
        match &segment[index] {
            ShellToken::Operator(operator) => match operator.as_str() {
                "(" | "{" | "((" => nesting += 1,
                ")" | "}" | "))" => nesting = (nesting - 1).max(0),
                operator if nesting == 0 && is_redirect_operator(operator) => {
                    if !budget.spend_node() {
                        break;
                    }
                    redirects.push(Redirect {
                        operator: operator.to_owned(),
                        target: segment
                            .get(index + 1)
                            .and_then(|token| word_from_token_at_depth(token, depth, budget)),
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

/// Redirects before a control opener or after its matching terminator belong
/// to the compound node. Redirects between those boundaries belong to the
/// parsed condition, body, or branch command that owns them.
fn redirects_around_control(
    segment: &[ShellToken],
    depth: usize,
    opener: usize,
    closer: usize,
    budget: &mut ShellParseBudget,
) -> Vec<Redirect> {
    let mut redirects = redirects_at_depth_zero(&segment[..opener], depth, budget);
    redirects.extend(redirects_at_depth_zero(
        &segment[closer + 1..],
        depth,
        budget,
    ));
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
    budget: &mut ShellParseBudget,
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
                args.push(
                    word_from_token_at_depth(&segment[index], depth, budget).expect("word token"),
                );
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

fn opaque_node() -> CommandNode {
    CommandNode::Opaque {
        words: Vec::new(),
        redirects: Vec::new(),
    }
}

fn word_from_token_at_depth(
    token: &ShellToken,
    depth: usize,
    budget: &mut ShellParseBudget,
) -> Option<Word> {
    let ShellToken::Word {
        value,
        substitutions,
        provenance,
        ..
    } = token
    else {
        return None;
    };
    if !budget.spend_node() {
        return Some(Word {
            value: value.clone(),
            provenance: *provenance,
            substitutions: Vec::new(),
        });
    }
    let mut parsed_substitutions = Vec::new();
    for substitution in substitutions {
        if !budget.spend_node() {
            break;
        }
        parsed_substitutions.push(ExecutedSubstitution {
            kind: substitution.kind,
            source: substitution.inner.clone(),
            program: match substitution.kind {
                SubstKind::Command | SubstKind::Process => {
                    child_program(&substitution.inner, depth + 1, budget)
                }
                SubstKind::Arithmetic => None,
            },
        });
    }
    Some(Word {
        value: value.clone(),
        provenance: *provenance,
        substitutions: parsed_substitutions,
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
    use crate::detect::shell::lexer::{SubstKind, tokenize};

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
                head_substitutions: Vec::new(),
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
                head_substitutions: Vec::new(),
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
    fn pipeline_conditions_use_final_status_and_negation() {
        let cases = [
            ("if true | false; then echo dead; fi", Reachability::Never),
            ("if false | true; then echo live; fi", Reachability::Always),
            ("if ! false; then echo live; fi", Reachability::Always),
            ("if ! true; then echo dead; fi", Reachability::Never),
        ];

        for (source, expected) in cases {
            let program = ShellProgram::from_units(vec![(1, source.to_owned())]);
            let CommandNode::If { then_body, .. } =
                &program.units()[0].statements[0].pipelines[0].commands[0]
            else {
                panic!("expected structured if for {source:?}");
            };
            assert_eq!(then_body[0].reachable, expected, "{source:?}");
        }
    }

    #[test]
    fn control_commands_preserve_their_surrounding_pipeline() {
        let program = ShellProgram::from_units(vec![(
            1,
            "if true; then base64 -d payload.b64; fi | sh".to_owned(),
        )]);
        let pipeline = &program.units()[0].statements[0].pipelines[0];
        assert_eq!(pipeline.commands.len(), 2);
        assert!(matches!(pipeline.commands[0], CommandNode::If { .. }));
        let CommandNode::Simple(command) = &pipeline.commands[1] else {
            panic!("expected interpreter pipeline consumer");
        };
        assert_eq!(command.head, "sh");
    }

    #[test]
    fn dead_elif_conditions_are_gated_and_case_patterns_do_not_nest_controls() {
        let program = ShellProgram::from_units(vec![
            (
                1,
                "if true; then :; elif curl https://example.test/dead; then :; fi".to_owned(),
            ),
            (
                2,
                "if false; then :; elif curl https://example.test/live; then :; fi".to_owned(),
            ),
        ]);
        for (unit, expected) in program
            .units()
            .iter()
            .zip([Reachability::Never, Reachability::Always])
        {
            let CommandNode::If { elif_branches, .. } =
                &unit.statements[0].pipelines[0].commands[0]
            else {
                panic!("expected structured if");
            };
            assert_eq!(elif_branches[0].condition[0].reachable, expected);
        }

        for pattern in [
            "if", "\"if\"", "fi", "\"fi\"", "case", "\"case\"", "done", "\"done\"",
        ] {
            let source = format!("case x in {pattern}) echo safe;; esac | sh");
            let program = ShellProgram::from_units(vec![(1, source)]);
            let pipeline = &program.units()[0].statements[0].pipelines[0];
            assert_eq!(pipeline.commands.len(), 2, "{pattern:?}");
            assert!(matches!(pipeline.commands[0], CommandNode::Case { .. }));
        }

        let program = ShellProgram::from_units(vec![(
            1,
            "case x in x) if true; then base64 -d payload.b64; fi;; esac | sh".to_owned(),
        )]);
        let pipeline = &program.units()[0].statements[0].pipelines[0];
        assert_eq!(pipeline.commands.len(), 2);
        let CommandNode::Case { branches, .. } = &pipeline.commands[0] else {
            panic!("expected structured case");
        };
        assert!(matches!(
            branches[0].body[0].pipelines[0].commands[0],
            CommandNode::If { .. }
        ));
    }

    #[test]
    fn for_word_lists_and_case_selectors_preserve_reserved_word_values() {
        for value in ["done", "if", "do", "case"] {
            let program = ShellProgram::from_units(vec![(
                1,
                format!("for x in {value}; do base64 -d payload.b64; done | sh"),
            )]);
            let pipeline = &program.units()[0].statements[0].pipelines[0];
            assert_eq!(pipeline.commands.len(), 2, "for x in {value}");
            assert!(matches!(pipeline.commands[0], CommandNode::For { .. }));
        }

        let program = ShellProgram::from_units(vec![(
            1,
            "case in in in) base64 -d payload.b64;; esac | sh".to_owned(),
        )]);
        let pipeline = &program.units()[0].statements[0].pipelines[0];
        assert_eq!(pipeline.commands.len(), 2);
        assert!(matches!(pipeline.commands[0], CommandNode::Case { .. }));

        for (source, assignment) in [
            ("\"A=B\"", false),
            ("A\\=B", false),
            ("A=B", true),
            ("A=\"B\"", true),
            ("A=$B", true),
        ] {
            let token = &tokenize(source)[0];
            assert_eq!(token.assignment_word().is_some(), assignment, "{source:?}");
        }
        assert!(tokenize("\"!\"")[0].syntax_word().is_none());
        assert!(tokenize("\\!")[0].syntax_word().is_none());
        assert_eq!(tokenize("!")[0].syntax_word(), Some("!"));
    }

    #[test]
    fn control_redirects_are_owned_by_their_boundaries() {
        let sources = [
            "if true; then echo body >body; :; fi >outer",
            "while true; do echo body >body; done >outer",
            "for item in one; do echo body >body; done >outer",
            "case x in x) echo body >body;; esac >outer",
        ];
        for source in sources {
            let program = ShellProgram::from_units(vec![(1, source.to_owned())]);
            let node = &program.units()[0].statements[0].pipelines[0].commands[0];
            let body = match node {
                CommandNode::If { then_body, .. }
                | CommandNode::Loop {
                    body: then_body, ..
                }
                | CommandNode::For {
                    body: then_body, ..
                } => then_body,
                CommandNode::Case { branches, .. } => &branches[0].body,
                _ => panic!("expected compound control for {source:?}"),
            };
            let redirects = match node {
                CommandNode::If { redirects, .. }
                | CommandNode::Loop { redirects, .. }
                | CommandNode::For { redirects, .. }
                | CommandNode::Case { redirects, .. } => redirects,
                _ => unreachable!(),
            };
            assert_eq!(redirects.len(), 1, "{source:?}");
            assert_eq!(redirects[0].target.as_ref().unwrap().value, "outer");
            let CommandNode::Simple(command) = &body[0].pipelines[0].commands[0] else {
                panic!("expected body command for {source:?}");
            };
            assert_eq!(command.redirects[0].target.as_ref().unwrap().value, "body");
        }
    }

    #[test]
    fn until_and_for_iteration_reachability_matches_shell_status_rules() {
        let cases = [
            ("until false; do echo live; done", Reachability::Always),
            ("for item in; do echo dead; done", Reachability::Never),
            ("for item; do echo maybe; done", Reachability::Maybe),
        ];

        for (source, expected) in cases {
            let program = ShellProgram::from_units(vec![(1, source.to_owned())]);
            let command = &program.units()[0].statements[0].pipelines[0].commands[0];
            let body = match command {
                CommandNode::Loop { body, .. } | CommandNode::For { body, .. } => body,
                _ => panic!("expected structured loop for {source:?}"),
            };
            assert_eq!(body[0].reachable, expected, "{source:?}");
        }
    }

    #[test]
    fn deeply_nested_substitutions_stop_at_the_analysis_depth_cap() {
        let source = format!("{}safe{}", "echo $(".repeat(5_000), ")".repeat(5_000));
        let program = ShellProgram::from_units(vec![(1, source)]);
        assert_eq!(program.units().len(), 1);
        assert!(!program.units()[0].statements.is_empty());
        assert!(program.requires_legacy_fallback());
    }

    #[test]
    fn multiline_process_substitution_is_bounded() {
        let source = "mapfile -t pids < <(\n  pgrep -x quickshell || true\n)\n";
        let units = super::super::source::shell_logical_units(
            source,
            &crate::detect::script::classify_heredoc_owner,
            &crate::detect::script::forwarded_body_fate,
        );
        let program = ShellProgram::from_units(units);
        assert_eq!(program.units().len(), 1);
        assert!(!program.units()[0].statements.is_empty());
    }

    #[test]
    fn child_programs_use_multiline_logical_and_heredoc_frontend() {
        let program = ShellProgram::from_source(
            "sh -c 'if false; then\n  curl https://example.test/dead\nfi'\n",
            0,
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
