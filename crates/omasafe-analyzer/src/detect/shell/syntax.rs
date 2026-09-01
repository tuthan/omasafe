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
        if token.syntax_word() == Some("!") {
            negations += 1;
        } else {
            break;
        }
    }
    negations % 2 == 1
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControlKind {
    If,
    Loop,
    Case,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CasePhase {
    Header,
    Patterns,
    Body,
}

#[derive(Clone, Copy)]
struct ControlFrame {
    kind: ControlKind,
    case_phase: CasePhase,
    case_header_word_seen: bool,
}

/// One shared shell-control scanner. All structural consumers use the same
/// command-position and case-pattern rules, so a quoted/escaped/expanded
/// reserved-word value never changes control nesting.
pub(in crate::detect) struct ControlScanner {
    groups: i32,
    controls: Vec<ControlFrame>,
    command_start: bool,
    case_separator_pending: bool,
    case_end_pending: bool,
}

impl ControlScanner {
    pub(in crate::detect) fn new() -> Self {
        Self {
            groups: 0,
            controls: Vec::new(),
            command_start: true,
            case_separator_pending: false,
            case_end_pending: false,
        }
    }

    pub(in crate::detect) fn control_depth(&self) -> i32 {
        self.controls.len() as i32
    }

    pub(in crate::detect) fn prepare(&mut self, token: &ShellToken) {
        if self.case_end_pending && token.operator() != Some(")") {
            if self
                .controls
                .last()
                .is_some_and(|frame| frame.kind == ControlKind::Case)
            {
                self.controls.pop();
            }
            self.case_end_pending = false;
        }
    }

    pub(in crate::detect) fn can_split(&self) -> bool {
        self.groups == 0 && self.controls.is_empty()
    }

    pub(in crate::detect) fn marker_at(
        &self,
        token: &ShellToken,
        next: Option<&ShellToken>,
        markers: &[&str],
        base_depth: i32,
    ) -> bool {
        if self.groups != 0 || self.control_depth() != base_depth {
            return false;
        }
        let Some(word) = token.syntax_word() else {
            return false;
        };
        let Some(top) = self.controls.last() else {
            return false;
        };

        if top.kind == ControlKind::Case && top.case_phase == CasePhase::Patterns {
            return word == "esac"
                && markers.contains(&"esac")
                && self.command_start
                && next.is_none_or(|candidate| candidate.operator() != Some(")"));
        }

        if word == "in"
            && markers.contains(&"in")
            && ((top.kind == ControlKind::Loop)
                || (top.kind == ControlKind::Case
                    && top.case_phase == CasePhase::Header
                    && top.case_header_word_seen))
        {
            return true;
        }

        self.command_start && markers.contains(&word)
    }

    pub(in crate::detect) fn step(&mut self, token: &ShellToken) {
        if let Some(operator) = token.operator() {
            match operator {
                "(" | "{" | "((" => {
                    self.groups += 1;
                    self.command_start = true;
                }
                ")" | "}" | "))" => {
                    if operator == ")"
                        && self.groups == 0
                        && self.controls.last().is_some_and(|frame| {
                            frame.kind == ControlKind::Case
                                && frame.case_phase == CasePhase::Patterns
                        })
                    {
                        if let Some(top) = self.controls.last_mut() {
                            top.case_phase = CasePhase::Body;
                        }
                        self.case_separator_pending = false;
                    }
                    self.groups = (self.groups - 1).max(0);
                    self.command_start = true;
                    if self.case_end_pending && operator == ")" {
                        self.case_end_pending = false;
                    }
                }
                ";" if self.groups == 0 => {
                    if let Some(top) = self.controls.last_mut()
                        && top.kind == ControlKind::Case
                        && top.case_phase == CasePhase::Body
                    {
                        if self.case_separator_pending {
                            top.case_phase = CasePhase::Patterns;
                            self.case_separator_pending = false;
                        } else {
                            self.case_separator_pending = true;
                        }
                    } else {
                        self.case_separator_pending = false;
                    }
                    self.command_start = true;
                }
                ";" | "&&" | "||" | "&" | "|" | "|&" => {
                    self.case_separator_pending = false;
                    self.command_start = true;
                }
                _ => {}
            }
            return;
        }

        let raw_word = token.word();
        let syntax_word = token.syntax_word();
        if raw_word.is_some() {
            self.case_separator_pending = false;
        }

        if self.groups == 0 {
            match self.controls.last().copied() {
                Some(ControlFrame {
                    kind: ControlKind::Case,
                    case_phase: CasePhase::Patterns,
                    ..
                }) => {
                    if syntax_word == Some("esac") && self.command_start {
                        self.case_end_pending = true;
                    }
                }
                Some(ControlFrame {
                    kind: ControlKind::Case,
                    case_phase: CasePhase::Header,
                    case_header_word_seen,
                }) => {
                    if syntax_word == Some("in") && case_header_word_seen {
                        if let Some(top) = self.controls.last_mut() {
                            top.case_phase = CasePhase::Patterns;
                        }
                    } else if raw_word.is_some()
                        && syntax_word != Some("in")
                        && let Some(top) = self.controls.last_mut()
                    {
                        top.case_header_word_seen = true;
                    }
                }
                Some(ControlFrame {
                    kind: ControlKind::If,
                    ..
                })
                | Some(ControlFrame {
                    kind: ControlKind::Loop,
                    ..
                })
                | Some(ControlFrame {
                    kind: ControlKind::Case,
                    case_phase: CasePhase::Body,
                    ..
                }) if self.command_start => {
                    if let Some(word) = syntax_word {
                        match word {
                            "if" => self.controls.push(ControlFrame {
                                kind: ControlKind::If,
                                case_phase: CasePhase::Header,
                                case_header_word_seen: false,
                            }),
                            "while" | "until" | "for" => self.controls.push(ControlFrame {
                                kind: ControlKind::Loop,
                                case_phase: CasePhase::Header,
                                case_header_word_seen: false,
                            }),
                            "case" => self.controls.push(ControlFrame {
                                kind: ControlKind::Case,
                                case_phase: CasePhase::Header,
                                case_header_word_seen: false,
                            }),
                            "fi" if self
                                .controls
                                .last()
                                .is_some_and(|frame| frame.kind == ControlKind::If) =>
                            {
                                self.controls.pop();
                            }
                            "done"
                                if self
                                    .controls
                                    .last()
                                    .is_some_and(|frame| frame.kind == ControlKind::Loop) =>
                            {
                                self.controls.pop();
                            }
                            "esac"
                                if self
                                    .controls
                                    .last()
                                    .is_some_and(|frame| frame.kind == ControlKind::Case) =>
                            {
                                self.case_end_pending = true;
                            }
                            _ => {}
                        }
                    }
                }
                None if self.command_start => {
                    if let Some(word) = syntax_word {
                        match word {
                            "if" => self.controls.push(ControlFrame {
                                kind: ControlKind::If,
                                case_phase: CasePhase::Header,
                                case_header_word_seen: false,
                            }),
                            "while" | "until" | "for" => self.controls.push(ControlFrame {
                                kind: ControlKind::Loop,
                                case_phase: CasePhase::Header,
                                case_header_word_seen: false,
                            }),
                            "case" => self.controls.push(ControlFrame {
                                kind: ControlKind::Case,
                                case_phase: CasePhase::Header,
                                case_header_word_seen: false,
                            }),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        self.command_start = syntax_word
            .is_some_and(|word| matches!(word, "!" | "then" | "elif" | "else" | "do" | "in"));
    }

    pub(in crate::detect) fn finish(&mut self) {
        if self.case_end_pending {
            if self
                .controls
                .last()
                .is_some_and(|frame| frame.kind == ControlKind::Case)
            {
                self.controls.pop();
            }
            self.case_end_pending = false;
        }
    }
}

/// Control depth for the logical-source assembler, using the same scanner as
/// pipeline and compound-command parsing.
pub(in crate::detect) fn control_flow_depth(tokens: &[ShellToken]) -> i32 {
    let mut scanner = ControlScanner::new();
    for token in tokens {
        scanner.prepare(token);
        scanner.step(token);
    }
    scanner.finish();
    scanner.control_depth()
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
    let mut scanner = ControlScanner::new();
    for (index, token) in tokens.iter().enumerate() {
        scanner.prepare(token);
        if let Some(op) = token.operator()
            && is_separator(op)
            && scanner.can_split()
        {
            segments.push(&tokens[start..index]);
            start = index + 1;
        }
        scanner.step(token);
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
