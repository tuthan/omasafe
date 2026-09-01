//! Command-position modeling over shell tokens.
//!
//! Extracted from `detect.rs` (plan A3): `ScriptCommand` and the parsers
//! that put a command in command position — prefix skipping, wrapper
//! unwrapping, argv collection, redirect semantics, and the
//! conditional-list exit-status model that reads command heads.

use super::lexer::ShellToken;
use super::syntax::{
    GroupKind, Outcomes, matching_group_close, pipeline_negated, pipeline_segments,
};
/// One command in command position inside a pipeline segment, with its
/// argument word values.
pub(in crate::detect) struct ScriptCommand<'a> {
    pub(in crate::detect) head: &'a str,
    pub(in crate::detect) args: Vec<&'a str>,
    /// Per-argument runtime-derivation flag parallel to `args`: an argument
    /// word carrying a substitution or an unquoted expansion resolves to
    /// text unknown until execution, so it is no static body candidate.
    pub(in crate::detect) arg_dynamic: Vec<bool>,
}

/// Commands in command position within one pipeline segment: the head word
/// (after `VAR=value` prefixes, leading redirections, `!` negation, and a
/// subshell/brace open), unwrapped through execution and privilege wrappers
/// (`sudo -u root chmod …`, `env curl …`, `exec curl …`, `time curl …` yield
/// the wrapper AND its wrapped command). Only a wrapper in command position
/// is unwrapped — wrapper words inside another command's argv
/// (`echo sudo chmod 777 /tmp/x`) remain operands.
pub(in crate::detect) fn segment_commands(segment: &[ShellToken]) -> Vec<ScriptCommand<'_>> {
    let mut commands = Vec::new();
    let mut index = 0usize;
    loop {
        skip_command_prefixes(segment, &mut index);
        let Some(head) = segment.get(index).and_then(ShellToken::word) else {
            break;
        };
        let basename = command_basename(head);
        let arguments = command_arguments(segment, index + 1);
        commands.push(ScriptCommand {
            head: basename,
            args: arguments.iter().map(|(value, _)| *value).collect(),
            arg_dynamic: arguments.iter().map(|(_, dynamic)| *dynamic).collect(),
        });
        if !matches!(
            basename,
            "sudo" | "pkexec" | "doas" | "command" | "env" | "exec" | "time"
        ) {
            break;
        }
        index += 1;
        // `env -S 'curl URL'` embeds the wrapped command as a word-split
        // string: record its head as a command of its own.
        if basename == "env"
            && let Some(script) = env_split_string_command(segment, index)
        {
            commands.push(script);
            break;
        }
        if !skip_wrapper_options(basename, segment, &mut index) {
            break;
        }
    }
    commands
}

/// The command embedded in an `env -S`/`--split-string` word, if the
/// wrapper's option area carries one: the string is word-split and its
/// first word executed (`env -S 'curl URL'` runs curl). Options and
/// assignments before it are skipped; a plain command word ends the scan.
pub(in crate::detect) fn env_split_string_command(
    segment: &[ShellToken],
    start: usize,
) -> Option<ScriptCommand<'_>> {
    let mut index = start;
    let mut value: Option<&str> = None;
    while value.is_none() {
        match segment.get(index)? {
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                index += 1;
                if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                    index += 1;
                }
            }
            ShellToken::Operator(_) => return None,
            ShellToken::Word { value: word, .. } => {
                let word = word.as_str();
                if is_env_assignment(word) {
                    index += 1;
                } else if word == "-S" || word == "--split-string" {
                    index += 1;
                    // A dangling `-S` carries no command string.
                    value = Some(segment.get(index).and_then(ShellToken::word)?);
                } else if let Some(rest) = word.strip_prefix("-S").filter(|rest| !rest.is_empty()) {
                    value = Some(rest);
                } else if let Some(rest) = word.strip_prefix("--split-string=") {
                    value = Some(rest);
                } else if let Some(long) = word.strip_prefix("--") {
                    if !long.contains('=') && wrapper_option_takes_value("env", long) {
                        advance_option_with_value(segment, &mut index);
                    } else {
                        index += 1;
                    }
                } else if word.len() > 1 && word.starts_with('-') {
                    if wrapper_option_takes_value("env", &word[1..]) {
                        advance_option_with_value(segment, &mut index);
                    } else {
                        index += 1;
                    }
                } else {
                    return None; // the command itself: no split-string present
                }
            }
        }
    }
    let mut words = value?.split_whitespace();
    let head = words.next()?;
    Some(ScriptCommand {
        head: command_basename(head),
        args: words.collect(),
        arg_dynamic: Vec::new(),
    })
}

pub(in crate::detect) fn is_env_assignment(token: &str) -> bool {
    let Some(equals) = token.find('=') else {
        return false;
    };
    equals > 0
        && token[..equals]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Argument word values of the command heading at `start`, each with its
/// runtime-derivation flag: every word except redirection operators and
/// their target words, so a redirect operand (`nc > -e host port`, `chmod >
/// 777 /tmp/x`) never reads as a detector flag or mode. Other operators
/// (leftover group punctuation) carry no argv.
pub(in crate::detect) fn command_arguments(
    segment: &[ShellToken],
    start: usize,
) -> Vec<(&str, bool)> {
    let mut args = Vec::new();
    let mut index = start;
    while index < segment.len() {
        match &segment[index] {
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                index += 1;
                if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                    index += 1; // the redirect target word
                }
            }
            ShellToken::Word { value, dynamic, .. } => {
                args.push((value.as_str(), *dynamic));
                index += 1;
            }
            ShellToken::Operator(_) => index += 1,
        }
    }
    args
}

/// Whether an operator token is a redirection (as opposed to a control
/// operator like `;`, `|`, `&&`): every redirection form contains `<` or `>`.
pub(in crate::detect) fn is_redirect_operator(op: &str) -> bool {
    op.contains('>') || op.contains('<')
}

/// Advance `index` past leading environment assignments, I/O redirections
/// (operator plus its target word), `!` pipeline negation, and a
/// subshell/brace open so the executable lands in command position:
/// `2>/dev/null VAR=x ! curl …` selects `curl`. An arithmetic command `((`
/// is NOT a prefix — its words are expression operands, never a command.
pub(in crate::detect) fn skip_command_prefixes(segment: &[ShellToken], index: &mut usize) {
    while let Some(token) = segment.get(*index) {
        match token {
            ShellToken::Word { value, .. } if value == "!" || is_env_assignment(value) => {
                *index += 1;
            }
            ShellToken::Operator(op) if op == "(" || op == "{" => *index += 1,
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                *index += 1;
                if matches!(segment.get(*index), Some(ShellToken::Word { .. })) {
                    *index += 1; // the redirect target word
                }
            }
            _ => break,
        }
    }
}

/// Consume a command-position wrapper's own arguments so the wrapped command
/// lands in command position: option clusters (`-n`, `-EH`, glued `-uroot`),
/// separate option values (`-u root`, `--user root`), `--`, redirections, and
/// environment prefixes. Returns whether the wrapper actually executes a
/// wrapped command — a plain word ends the scan with `true`, while
/// `command -v curl` only describes curl and yields `false`.
pub(in crate::detect) fn skip_wrapper_options(
    wrapper: &str,
    segment: &[ShellToken],
    index: &mut usize,
) -> bool {
    while let Some(token) = segment.get(*index) {
        match token {
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                *index += 1;
                if matches!(segment.get(*index), Some(ShellToken::Word { .. })) {
                    *index += 1;
                }
            }
            ShellToken::Operator(op) if op == "(" => *index += 1,
            ShellToken::Operator(_) => return false,
            ShellToken::Word { value, .. } => {
                let token = value.as_str();
                if is_env_assignment(token) {
                    *index += 1;
                } else if token == "--" {
                    *index += 1;
                    return true;
                } else if let Some(long) = token.strip_prefix("--") {
                    if !long.contains('=') && wrapper_option_takes_value(wrapper, long) {
                        advance_option_with_value(segment, index);
                    } else {
                        *index += 1;
                    }
                } else if token.len() > 1 && token.starts_with('-') {
                    let flags = &token[1..];
                    if wrapper == "command" && flags.contains(['v', 'V']) {
                        return false; // describe-only: nothing executes
                    }
                    if flags.len() == 1 && wrapper_option_takes_value(wrapper, flags) {
                        advance_option_with_value(segment, index);
                    } else {
                        *index += 1;
                    }
                } else {
                    return true; // the wrapped command
                }
            }
        }
    }
    false // options ran off the end: no wrapped command
}

/// Skip an option and its separate value word (`-u root`, `--user root`).
fn advance_option_with_value(segment: &[ShellToken], index: &mut usize) {
    *index += 1;
    if matches!(segment.get(*index), Some(ShellToken::Word { .. })) {
        *index += 1;
    }
}

/// Sudo-family options that take a separate value token, matched on the bare
/// name; glued values (`-uroot`, `--user=root`) need no special case.
fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    match wrapper {
        "sudo" => matches!(
            option,
            "u" | "g"
                | "p"
                | "C"
                | "T"
                | "D"
                | "R"
                | "U"
                | "user"
                | "group"
                | "other-user"
                | "prompt"
                | "close-from"
                | "chdir"
                | "type"
                | "role"
                | "context"
                | "host"
                | "command-timeout"
        ),
        // `command` takes no valued options; `-p` is a bare flag. `-v`/`-V`
        // never reach here — they stop the unwrap (describe-only).
        "command" => false,
        "env" => matches!(
            option,
            "u" | "unset"
                | "chdir"
                | "split-string"
                | "block-signal"
                | "default-signal"
                | "ignore-signal"
        ),
        "pkexec" => option == "user",
        "doas" => option == "u",
        "exec" => option == "a", // exec -a NAME
        // GNU time: -f/--format and -o/--output take a value; -a is a flag.
        "time" => matches!(option, "f" | "o" | "format" | "output"),
        _ => false,
    }
}

/// The outcomes a statement contributes to the following guards: its
/// pipeline's LAST command decides the exit status (`false | true`
/// succeeds), and a leading `!` negation inverts a known status
/// (`! true` fails, `! false` succeeds).
pub(in crate::detect) fn statement_outcomes(statement: &[ShellToken]) -> Outcomes {
    let segment = pipeline_segments(statement)
        .last()
        .copied()
        .unwrap_or(statement);
    let (success, failure) = match segment_commands(segment).last().map(|command| command.head) {
        Some("true") | Some(":") => (true, false),
        Some("false") => (false, true),
        _ => (true, true),
    };
    if pipeline_negated(statement) {
        Outcomes {
            success: failure,
            failure: success,
        }
    } else {
        Outcomes { success, failure }
    }
}

/// Whether a redirection operator (with its target word) moves fd 1 off the
/// pipeline. The affected descriptor is the explicit fd digits, else 1 for
/// `>` forms and 0 for `<` forms; `&>` moves both streams; a duplication
/// (`>&m`) keeps stdout only when duplicated onto itself.
pub(in crate::detect) fn redirect_moves_stdout_away(op: &str, target: &str) -> bool {
    let digits_end = op.bytes().take_while(u8::is_ascii_digit).count();
    let rest = &op[digits_end..];
    if rest == "&>" || rest == "&>>" {
        return true; // both stdout and stderr redirected
    }
    let default_fd = if rest.starts_with('>') { 1 } else { 0 };
    let fd = op[..digits_end].parse::<u32>().unwrap_or(default_fd);
    if fd != 1 {
        return false; // stderr-only (or other) redirects keep the pipe fed
    }
    match rest {
        ">&" | "<&" => target != "1", // duplication stays only onto itself
        _ => true,                    // >, >>, <, <>, << on fd 1 all leave the pipe
    }
}

/// Any I/O redirection operator in the segment.
pub(in crate::detect) fn segment_has_redirect_op(segment: &[ShellToken]) -> bool {
    segment
        .iter()
        .filter_map(ShellToken::operator)
        .any(is_redirect_operator)
}

/// Redirect operators at the segment's own nesting depth: redirects inside
/// compound groups belong to the inner commands that carry them, while
/// depth-zero redirects belong to the (possibly compound) command itself.
fn depth_zero_redirect(segment: &[ShellToken], mut moves: impl FnMut(&str, &str) -> bool) -> bool {
    let mut depth = 0i32;
    let mut index = 0usize;
    while index < segment.len() {
        if let Some(op) = segment[index].operator() {
            match op {
                "(" | "{" | "((" => depth += 1,
                ")" | "}" | "))" => depth = (depth - 1).max(0),
                _ if depth == 0 && is_redirect_operator(op) => {
                    let target = segment
                        .get(index + 1)
                        .and_then(ShellToken::word)
                        .unwrap_or("");
                    if moves(op, target) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    false
}

pub(in crate::detect) fn depth_zero_redirect_moves_stdout(segment: &[ShellToken]) -> bool {
    depth_zero_redirect(segment, redirect_moves_stdout_away)
}

pub(in crate::detect) fn depth_zero_redirect_moves_stdin_away(segment: &[ShellToken]) -> bool {
    depth_zero_redirect(segment, redirect_moves_stdin_away)
}

/// Whether a redirection operator (with its target word) replaces the
/// compound's stdin: fd 0 moved anywhere except back onto itself
/// (`<file`, `0</dev/null`, `<<EOF`, `<&-` starve everything inside;
/// `2<&1` and `0<&0` do not touch stdin).
pub(in crate::detect) fn redirect_moves_stdin_away(op: &str, target: &str) -> bool {
    let digits_end = op.bytes().take_while(u8::is_ascii_digit).count();
    let rest = &op[digits_end..];
    let default_fd = if rest.starts_with('<') { 0 } else { 1 };
    let fd = op[..digits_end].parse::<u32>().unwrap_or(default_fd);
    if fd != 0 {
        return false;
    }
    match rest {
        "<&" | ">&" => target != "0", // duplication stays only onto itself
        _ => true,                    // <, <<, <> on fd 0 all replace stdin
    }
}

/// The compound group opening at the segment's command position (after the
/// usual prefixes), with its interior: `None` when the segment heads a plain
/// command.
pub(in crate::detect) fn compound_position(
    segment: &[ShellToken],
) -> Option<(GroupKind, &[ShellToken])> {
    let mut index = 0usize;
    while let Some(token) = segment.get(index) {
        match token {
            ShellToken::Operator(op) => {
                let op = op.as_str();
                if op == "(" || op == "{" || op == "((" {
                    let kind = if op == "((" {
                        GroupKind::Arithmetic
                    } else {
                        GroupKind::List
                    };
                    let close = matching_group_close(segment, index)?;
                    return Some((kind, &segment[index + 1..close]));
                } else if is_redirect_operator(op) {
                    index += 1;
                    if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                        index += 1; // the redirect target word
                    }
                } else {
                    return None;
                }
            }
            ShellToken::Word { value, .. } if value == "!" || is_env_assignment(value) => {
                index += 1;
            }
            _ => return None,
        }
    }
    None
}

/// Basename of a command token, tolerating prefixed punctuation left in a
/// value by a substitution head (`$(curl`, `/usr/bin/nc`).
pub(in crate::detect) fn command_basename(token: &str) -> &str {
    if token == "." {
        return token;
    }
    let trimmed = token.trim_start_matches(|character: char| !character.is_ascii_alphanumeric());
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}
