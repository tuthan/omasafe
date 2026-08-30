//! Fetch attribution for shell script text.
//!
//! Extracted from `detect.rs` (plan A4): the executed-path walk that finds a
//! fetch tool in command position anywhere the script runs — statements,
//! pipeline segments, compound groups, and active command/process
//! substitutions — plus the segment/group command search it is built on.

use super::budget::ShellBudget;
use super::command::{ScriptCommand, segment_commands, statement_outcomes};
use super::effects::command_fetches;
use super::interpreter::static_command_body;
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
        if !budget.enter() {
            return false;
        }
        let found = tokens_fetch_egress(&tokenize(&body), budget);
        budget.leave();
        found
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
                if !budget.enter() {
                    return false;
                }
                let found = tokens_fetch_egress(&tokenize(&substitution.inner), budget);
                budget.leave();
                found
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
    let fetches = tokens_fetch_egress(&tokenize(script), &mut budget);
    (fetches, budget.exhausted())
}
