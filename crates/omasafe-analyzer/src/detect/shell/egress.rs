//! Fetch attribution for shell script text.
//!
//! Extracted from `detect.rs` (plan A4): the executed-path walk that finds a
//! fetch tool in command position anywhere the script runs — statements,
//! pipeline segments, compound groups, and active command/process
//! substitutions — plus the segment/group command search it is built on.

use super::budget::ShellBudget;
use super::command::{
    ScriptCommand, redirect_moves_stdout_away, segment_commands, statement_outcomes,
};
use super::effects::{
    CommandEffects, EgressEffect, StdoutEffect, command_fetches, ir_command_effects,
    ir_node_stdout_preserved,
};
use super::interpreter::static_command_body;
use super::ir::{CommandNode, LogicalUnit, ShellProgram, Statement};
use super::lexer::{ShellToken, SubstKind, Substitution, tokenize};
use super::syntax::{
    GroupKind, Outcomes, conditional_statements, grouped_token_ranges, matching_group_close,
    pipeline_segments,
};

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

/// A fetch tool in command position anywhere the script actually runs —
/// across executed statements and pipeline segments (including inside
/// compound groups, whose own statements keep their guards), and
/// recursively inside every active command or process substitution, so
/// `payload="$(curl …)"` and `(echo x; curl URL) | sh` attribute egress
/// while `echo curl …`, single-quoted prose, and short-circuited branches
/// (`false && curl URL`) do not.
pub(in crate::detect) fn tokens_fetch_egress(
    tokens: &[ShellToken],
    budget: &mut ShellBudget,
) -> bool {
    if !budget.spend(tokens.len()) {
        return false;
    }
    executed_list_fetch_egress(tokens, budget)
}

/// Direct command-position fetches are read from the typed shell IR,
/// including child programs owned by static bodies and substitutions.
/// Unsupported or depth-capped children remain on the token fallback.
pub(in crate::detect) fn unit_has_direct_fetch(
    unit: &LogicalUnit,
    budget: &mut ShellBudget,
) -> bool {
    statements_have_direct_fetch(&unit.statements, budget)
}

fn statements_have_direct_fetch(statements: &[Statement], budget: &mut ShellBudget) -> bool {
    statements.iter().any(|statement| {
        statement.reachable.is_reachable()
            && statement.pipelines.iter().any(|pipeline| {
                pipeline
                    .commands
                    .iter()
                    .any(|node| node_has_direct_fetch(node, budget))
            })
    })
}

fn node_has_direct_fetch(node: &CommandNode, budget: &mut ShellBudget) -> bool {
    if !budget.spend(1) {
        return false;
    }
    match node {
        CommandNode::Simple(command) => {
            matches!(command.head.as_str(), "curl" | "wget")
                || command
                    .body
                    .as_ref()
                    .and_then(|body| body.program.as_deref())
                    .is_some_and(|program| program_has_direct_fetch(program, budget))
                || command.args.iter().any(|word| {
                    word.substitutions.iter().any(|substitution| {
                        substitution
                            .program
                            .as_deref()
                            .is_some_and(|program| program_has_direct_fetch(program, budget))
                    })
                })
        }
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            statements_have_direct_fetch(body, budget)
        }
        CommandNode::Arithmetic { .. } | CommandNode::Opaque { .. } => false,
        CommandNode::If {
            condition,
            then_body,
            elif_branches,
            else_body,
            ..
        } => {
            statements_have_direct_fetch(condition, budget)
                || statements_have_direct_fetch(then_body, budget)
                || elif_branches.iter().any(|branch| {
                    statements_have_direct_fetch(&branch.condition, budget)
                        || statements_have_direct_fetch(&branch.body, budget)
                })
                || statements_have_direct_fetch(else_body, budget)
        }
        CommandNode::Loop {
            condition, body, ..
        } => {
            statements_have_direct_fetch(condition, budget)
                || statements_have_direct_fetch(body, budget)
        }
        CommandNode::For { body, .. } => statements_have_direct_fetch(body, budget),
        CommandNode::Case { word, branches, .. } => {
            word.substitutions.iter().any(|substitution| {
                substitution
                    .program
                    .as_deref()
                    .is_some_and(|program| program_has_direct_fetch(program, budget))
            }) || branches
                .iter()
                .any(|branch| statements_have_direct_fetch(&branch.body, budget))
        }
    }
}

fn node_stdout_redirected(node: &CommandNode) -> bool {
    let redirects = match node {
        CommandNode::Simple(command) => &command.redirects,
        CommandNode::Subshell { redirects, .. }
        | CommandNode::BraceGroup { redirects, .. }
        | CommandNode::Arithmetic { redirects, .. }
        | CommandNode::If { redirects, .. }
        | CommandNode::Loop { redirects, .. }
        | CommandNode::For { redirects, .. }
        | CommandNode::Case { redirects, .. }
        | CommandNode::Opaque { redirects, .. } => redirects,
    };
    redirects.iter().any(|redirect| {
        redirect_moves_stdout_away(
            &redirect.operator,
            redirect
                .target
                .as_ref()
                .map_or("", |target| target.value.as_str()),
        )
    })
}

fn program_has_direct_fetch(program: &ShellProgram, budget: &mut ShellBudget) -> bool {
    program
        .units()
        .iter()
        .any(|unit| statements_have_direct_fetch(&unit.statements, budget))
}

/// Whether a typed child program emits a live fetch response on its own
/// stdout. This is the child-IR equivalent of `body_live_fetch_stdout`; it
/// composes typed pipeline forwarding without tokenizing the body again.
pub(in crate::detect) fn ir_program_live_fetch_stdout(
    program: &ShellProgram,
    budget: &mut ShellBudget,
) -> bool {
    if !budget.spend(1) {
        return false;
    }
    program.units().iter().any(|unit| {
        unit.statements
            .iter()
            .filter(|statement| statement.reachable.is_reachable())
            .any(|statement| {
                statement.pipelines.iter().any(|pipeline| {
                    (0..pipeline.commands.len()).any(|producer| {
                        node_has_live_fetch_stdout(&pipeline.commands[producer], budget)
                            && pipeline.commands[producer + 1..]
                                .iter()
                                .all(|node| ir_node_stdout_preserved(node, budget))
                    })
                })
            })
    })
}

/// Typed live-fetch output for one pipeline node, including a static body or
/// a compound group's own child statements.
pub(in crate::detect) fn node_has_live_fetch_stdout(
    node: &CommandNode,
    budget: &mut ShellBudget,
) -> bool {
    node_has_live_fetch_stdout_with_effects(node, budget, None)
}

/// Typed live-fetch output with an optional command summary supplied by the
/// caller. The pipeline dataflow pass uses this to avoid recalculating a
/// simple node's command effects.
pub(in crate::detect) fn node_has_live_fetch_stdout_with_effects(
    node: &CommandNode,
    budget: &mut ShellBudget,
    supplied_effects: Option<CommandEffects>,
) -> bool {
    if !budget.spend(1) {
        return false;
    }
    if node_stdout_redirected(node) {
        return false;
    }
    match node {
        CommandNode::Simple(command) => {
            let effects = supplied_effects.unwrap_or_else(|| ir_command_effects(command, budget));
            if effects.stdout == StdoutEffect::Redirected {
                return false;
            }
            effects.egress == EgressEffect::NetworkFetch
                || command
                    .body
                    .as_ref()
                    .and_then(|body| body.program.as_deref())
                    .is_some_and(|program| ir_program_live_fetch_stdout(program, budget))
        }
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            statements_live_fetch_stdout(body, budget)
        }
        CommandNode::Arithmetic { .. } | CommandNode::Opaque { .. } => false,
        CommandNode::If {
            condition,
            then_body,
            elif_branches,
            else_body,
            ..
        } => {
            statements_live_fetch_stdout(condition, budget)
                || statements_live_fetch_stdout(then_body, budget)
                || elif_branches.iter().any(|branch| {
                    statements_live_fetch_stdout(&branch.condition, budget)
                        || statements_live_fetch_stdout(&branch.body, budget)
                })
                || statements_live_fetch_stdout(else_body, budget)
        }
        CommandNode::Loop {
            condition, body, ..
        } => {
            statements_live_fetch_stdout(condition, budget)
                || statements_live_fetch_stdout(body, budget)
        }
        CommandNode::For { body, .. } => statements_live_fetch_stdout(body, budget),
        CommandNode::Case { branches, .. } => branches
            .iter()
            .any(|branch| statements_live_fetch_stdout(&branch.body, budget)),
    }
}

fn statements_live_fetch_stdout(statements: &[Statement], budget: &mut ShellBudget) -> bool {
    statements
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
        .any(|statement| {
            statement.pipelines.iter().any(|pipeline| {
                (0..pipeline.commands.len()).any(|producer| {
                    node_has_live_fetch_stdout(&pipeline.commands[producer], budget)
                        && pipeline.commands[producer + 1..]
                            .iter()
                            .all(|node| ir_node_stdout_preserved(node, budget))
                })
            })
        })
}

/// Analyze a re-parsed shell body with the shared bounded cache. The cache is
/// keyed by the exact body text and stores only completed results, so a body
/// that exhausts the analysis budget is never reused as if it were clean.
pub(in crate::detect) fn body_fetches_egress(body: &str, budget: &mut ShellBudget) -> bool {
    if budget.exhausted() {
        return false;
    }
    if let Some(fetches) = budget.cached_fetch_egress(body) {
        return fetches;
    }
    if !budget.enter() {
        return false;
    }
    let fetches = tokens_fetch_egress(&tokenize(body), budget);
    budget.leave();
    if !budget.exhausted() {
        budget.cache_fetch_egress(body, fetches);
    }
    fetches
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
        body_fetches_egress(&body, budget)
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
                body_fetches_egress(&substitution.inner, budget)
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
pub(in crate::detect) fn script_body_fetches(script: &str) -> (bool, bool) {
    let mut budget = ShellBudget::new();
    let fetches = body_fetches_egress(script, &mut budget);
    (fetches, budget.exhausted())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::shell::ir::ShellProgram;

    #[test]
    fn body_egress_summaries_are_reused_for_positive_and_negative_results() {
        let mut budget = ShellBudget::new();
        assert!(body_fetches_egress(
            "curl https://example.test/x",
            &mut budget
        ));
        let nodes_after_fetch = budget.nodes;
        assert!(body_fetches_egress(
            "curl https://example.test/x",
            &mut budget
        ));
        assert_eq!(budget.nodes, nodes_after_fetch);

        assert!(!body_fetches_egress("echo safe", &mut budget));
        let nodes_after_safe = budget.nodes;
        assert!(!body_fetches_egress("echo safe", &mut budget));
        assert_eq!(budget.nodes, nodes_after_safe);
        assert!(!budget.exhausted());
    }

    #[test]
    fn typed_ir_direct_fetches_honor_guards_and_compounds() {
        let cases = [
            ("false && curl https://example.test/dead", false),
            ("false || curl https://example.test/live", true),
            ("sudo -n curl https://example.test/wrapped", true),
            ("(false && wget https://example.test/dead)", false),
            ("echo 'curl https://example.test/data'", false),
            ("sh -c 'curl https://example.test/body'", true),
            ("echo \"$(wget https://example.test/sub)\"", true),
        ];

        for (source, expected) in cases {
            let program = ShellProgram::from_units(vec![(1, source.to_owned())]);
            let mut budget = ShellBudget::new();
            assert_eq!(
                unit_has_direct_fetch(&program.units()[0], &mut budget),
                expected,
                "typed direct-fetch result for {source:?}"
            );
        }
    }
}
