//! Statement, pipeline, and compound-group structure over shell tokens.
//!
//! Extracted from `detect.rs` (plan A3): statement splitting with the
//! control operator that precedes each one, the conditional-list outcome
//! set, pipeline segmentation, and compound-group discovery.

use super::lexer::ShellToken;
/// Statements of a token slice with the control operator that preceded each
/// one (`;`, `&&`, `||`, `&`; the first statement carries `None`), so
/// conditional lists keep their short-circuit semantics instead of every
/// statement reading as executed sequentially.
pub(in crate::detect) fn conditional_statements(
    tokens: &[ShellToken],
) -> Vec<(&[ShellToken], Option<&str>)> {
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut guard: Option<&str> = None;
    let mut depth = 0i32;
    for (index, token) in tokens.iter().enumerate() {
        if let Some(op) = token.operator() {
            match op {
                "(" | "{" | "((" => depth += 1,
                ")" | "}" | "))" => depth = (depth - 1).max(0),
                ";" | "&&" | "||" | "&" if depth == 0 => {
                    statements.push((&tokens[start..index], guard));
                    guard = Some(op);
                    start = index + 1;
                }
                _ => {}
            }
        }
    }
    statements.push((&tokens[start..], guard));
    statements
}

/// Exit-status model for conditional lists as the SET of statuses the
/// preceding list may still end with. Only `true`/`:` and `false` are known;
/// every other command contributes BOTH, so each following guard stays
/// executable on the paths where it applies. A guarded statement that runs
/// replaces the executed paths' statuses with its own while skipped paths
/// keep theirs — `printf ok || false && curl …` still reaches the fetch on
/// the printf-success path even though the `false` path never does.
#[derive(Clone, Copy)]
pub(in crate::detect) struct Outcomes {
    pub(in crate::detect) success: bool,
    pub(in crate::detect) failure: bool,
}

impl Outcomes {
    /// Before any statement every path is live, so both statuses are
    /// possible (the first statement's guard is always unconditional).
    pub(in crate::detect) const ANY: Self = Self {
        success: true,
        failure: true,
    };

    /// Whether a statement runs given the operator before it and the
    /// modelled outcomes of the previous statement.
    pub(in crate::detect) fn executes(self, guard: Option<&str>) -> bool {
        match guard {
            None | Some(";") | Some("&") => true,
            Some("&&") => self.success,
            Some("||") => self.failure,
            _ => true,
        }
    }

    /// The outcomes AFTER one guarded statement: executed paths take the
    /// statement's own statuses, skipped paths keep the previous ones.
    pub(in crate::detect) fn advance(self, guard: Option<&str>, statement: Self) -> Self {
        match guard {
            Some("&&") => Self {
                success: self.success && statement.success,
                failure: (self.success && statement.failure) || self.failure,
            },
            Some("||") => Self {
                success: (self.failure && statement.success) || self.success,
                failure: self.failure && statement.failure,
            },
            _ => statement,
        }
    }
}

/// Whether the statement negates its pipeline with the `!` reserved word —
/// `!` opens a pipeline, so nothing can precede it, and `! ! cmd` negates
/// twice.
pub(in crate::detect) fn pipeline_negated(statement: &[ShellToken]) -> bool {
    let mut negations = 0usize;
    for token in statement {
        match token {
            ShellToken::Word { value, .. } if value == "!" => negations += 1,
            _ => break,
        }
    }
    negations % 2 == 1
}

/// Split a statement into outer pipeline segments on `|` and Bash's `|&`
/// (which pipes stdout AND stderr). Separators inside a control command's
/// condition or body stay inside that command; a separator after `fi`,
/// `done`, or `esac` still splits the surrounding pipeline.
pub(in crate::detect) fn pipeline_segments(tokens: &[ShellToken]) -> Vec<&[ShellToken]> {
    split_token_stream(tokens, |op| op == "|" || op == "|&")
}

fn split_token_stream(
    tokens: &[ShellToken],
    is_separator: impl Fn(&str) -> bool,
) -> Vec<&[ShellToken]> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut controls = Vec::new();
    let mut command_start = true;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            ShellToken::Operator(op) => match op.as_str() {
                "(" | "{" | "((" => {
                    depth += 1;
                    command_start = true;
                }
                ")" | "}" | "))" => {
                    depth = (depth - 1).max(0);
                    command_start = true;
                }
                _ if depth == 0 && is_separator(op) && controls.is_empty() => {
                    segments.push(&tokens[start..index]);
                    start = index + 1;
                    command_start = true;
                }
                "|" | "|&" | ";" | "&&" | "||" | "&" => command_start = true,
                _ => {}
            },
            ShellToken::Word { value, .. } => {
                if depth == 0 && command_start {
                    match value.as_str() {
                        "if" => controls.push("if"),
                        "while" | "until" | "for" => controls.push("loop"),
                        "case" => controls.push("case"),
                        "fi" if controls.last() == Some(&"if") => {
                            controls.pop();
                        }
                        "done" if controls.last() == Some(&"loop") => {
                            controls.pop();
                        }
                        "esac" if controls.last() == Some(&"case") => {
                            controls.pop();
                        }
                        _ => {}
                    }
                }
                command_start = value == "!"
                    || matches!(value.as_str(), "then" | "elif" | "else" | "do" | "in");
            }
        }
    }
    segments.push(&tokens[start..]);
    segments
}

/// Kind of a compound group's interior: `(`/`{` wrap a command list the
/// subshell runs, `((` wraps an arithmetic expression whose words are
/// variables and never commands.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::detect) enum GroupKind {
    List,
    Arithmetic,
}

/// Token index of the closer matching the group opener at `open_index`,
/// counting any opener/closer pair as one nesting level (mirroring
/// `split_token_stream`). `None` when the group never closes.
pub(in crate::detect) fn matching_group_close(
    tokens: &[ShellToken],
    open_index: usize,
) -> Option<usize> {
    let mut depth = 1i32;
    for (offset, token) in tokens[open_index + 1..].iter().enumerate() {
        match token.operator() {
            Some("(" | "{" | "((") => depth += 1,
            Some(")" | "}" | "))") => {
                depth -= 1;
                if depth == 0 {
                    return Some(open_index + 1 + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// Top-level compound groups of a token slice, left to right and
/// non-overlapping: subshell and brace groups hold a command list the shell
/// runs, an arithmetic command holds an expression. Nested groups are NOT
/// returned here — the caller recurses into the returned interiors, which
/// re-discovers them, so descendants are analyzed once instead of once per
/// enclosing ancestor, and nothing nested inside an arithmetic group is ever
/// surfaced as a command list (`(( (curl URL | sh) ))` runs nothing).
pub(in crate::detect) fn grouped_token_ranges(
    tokens: &[ShellToken],
) -> Vec<(GroupKind, &[ShellToken])> {
    let mut groups = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let kind = match tokens[index].operator() {
            Some("(" | "{") => GroupKind::List,
            Some("((") => GroupKind::Arithmetic,
            _ => {
                index += 1;
                continue;
            }
        };
        match matching_group_close(tokens, index) {
            Some(close) => {
                groups.push((kind, &tokens[index + 1..close]));
                index = close + 1;
            }
            None => index += 1, // unmatched opener: keep scanning past it
        }
    }
    groups
}
