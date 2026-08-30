//! Shell logical-source assembly: physical lines become whole logical
//! command units, with comments applied statefully and heredoc payloads
//! kept out of top-level command scanning.

use super::lexer::{ShellToken, tokenize};
use crate::detect::{
    InterpreterFamily, InterpreterMode, interpreter_family, interpreter_mode, segment_commands,
};

/// Whether the assembled text ends with an open pipeline or list operator —
/// the grammar demands the next line (`curl URL |`, `fetch &&`).
fn trailing_pipeline_operator(text: &str) -> bool {
    matches!(
        tokenize(text).last().and_then(ShellToken::operator),
        Some("|" | "|&" | "&&" | "||")
    )
}

/// Shell source assembled into LOGICAL command units: a unit continues
/// across escaped newlines (backslash-newline removed, no byte inserted),
/// trailing `|`/`|&`/`&&`/`||` operators, and open quotes, backticks, or
/// `(`/`{` groups, so a pipeline split over physical lines tokenizes whole
/// (`curl URL \` + `| sh`, `curl URL |` + `sh`). Comments are applied
/// statefully along the way — a `#` at a word boundary drops the rest of
/// its line, and a backslash-newline inside a comment never continues.
/// Each unit keeps its STARTING line number for findings.
pub(in crate::detect) fn shell_logical_units(source: &str) -> Vec<(u32, String)> {
    let source = shell_source_without_heredoc_payloads(source);
    let mut units: Vec<(u32, String)> = Vec::new();
    let mut text = String::new();
    let mut start_line = 1u32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    let mut open = false;
    for (index, raw_line) in source.lines().enumerate() {
        if !open {
            start_line = index as u32 + 1;
        }
        let mut escaped_newline = false;
        let mut boundary = true; // a line start is a word boundary for `#`
        let mut characters = raw_line.chars().peekable();
        while let Some(character) = characters.next() {
            if in_single {
                if character == '\'' {
                    in_single = false;
                }
                text.push(character);
                boundary = false;
                continue;
            }
            if in_backtick {
                if character == '`' {
                    in_backtick = false;
                }
                text.push(character);
                boundary = false;
                continue;
            }
            if in_double {
                if character == '\\' {
                    match characters.next() {
                        // A backslash-newline continues even inside quotes.
                        None => escaped_newline = true,
                        Some(next) => {
                            text.push(character);
                            text.push(next);
                        }
                    }
                } else if character == '"' {
                    in_double = false;
                    text.push(character);
                } else {
                    text.push(character);
                }
                boundary = false;
                continue;
            }
            if character == '\\' {
                match characters.next() {
                    None => escaped_newline = true,
                    Some(next) => {
                        text.push(character);
                        text.push(next);
                    }
                }
                boundary = false;
                continue;
            }
            // A `#` at a word boundary comments out the rest of the line —
            // including any trailing backslash continuation.
            if character == '#' && boundary {
                break;
            }
            text.push(character);
            boundary = matches!(character, ' ' | '\t' | ';' | '&' | '|' | '(');
            match character {
                '\'' => in_single = true,
                '"' => in_double = true,
                '`' => in_backtick = true,
                _ => {}
            }
        }
        if escaped_newline {
            open = true; // the backslash-newline is removed: join directly
            continue;
        }
        // The lexer, rather than raw bytes, decides whether a compound list
        // remains open. In particular `foo{` and an escaped `\\|` are words,
        // not group/pipeline syntax.
        let token_depth =
            tokenize(&text)
                .iter()
                .fold(0i32, |depth, token| match token.operator() {
                    Some("(" | "{" | "((") => depth + 1,
                    Some(")" | "}" | "))") => (depth - 1).max(0),
                    _ => depth,
                });
        open = in_single
            || in_double
            || in_backtick
            || token_depth > 0
            || trailing_pipeline_operator(&text);
        if open {
            // Newlines in a compound list remain statement separators; a
            // grammar-required operator continuation is whitespace instead.
            if token_depth > 0 && !trailing_pipeline_operator(&text) {
                text.push(';');
            } else {
                text.push(' ');
            }
        } else if !text.trim().is_empty() {
            let assembled = std::mem::take(&mut text);
            units.push((start_line, assembled.trim_end().to_owned()));
            in_single = false;
            in_double = false;
            in_backtick = false;
        }
    }
    if !text.trim().is_empty() {
        units.push((start_line, text.trim_end().to_owned()));
    }
    units
}

/// Remove heredoc payload lines from ordinary command scanning. A heredoc is
/// data unless its owning command is a shell interpreter; for that one case,
/// rewrite the static stdin script into an equivalent `-c` body so the normal
/// bounded shell walks can inspect code without treating `cat <<EOF` data as
/// top-level commands. Delimiters are tokenized, so quotes are removed only
/// for comparison; `<<-` accepts leading tabs on its terminator.
fn shell_source_without_heredoc_payloads(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut output = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index];
        let tokens = tokenize(line);
        let Some(redirection) = tokens
            .iter()
            .position(|token| matches!(token.operator(), Some("<<" | "<<-")))
        else {
            output.push(line.to_owned());
            index += 1;
            continue;
        };
        let strip_tabs = tokens[redirection].operator() == Some("<<-");
        let Some(delimiter) = tokens.get(redirection + 1).and_then(ShellToken::word) else {
            output.push(line.to_owned());
            index += 1;
            continue;
        };
        let mut body = Vec::new();
        let mut cursor = index + 1;
        while cursor < lines.len() {
            let candidate = if strip_tabs {
                lines[cursor].trim_start_matches('\t')
            } else {
                lines[cursor]
            };
            if candidate == delimiter {
                break;
            }
            body.push(lines[cursor]);
            cursor += 1;
        }
        // An unterminated heredoc is left alone: treating the rest of the
        // file as data would hide live code after malformed input.
        if cursor == lines.len() {
            output.push(line.to_owned());
            index += 1;
            continue;
        }
        let shell_owner = segment_commands(&tokens).first().is_some_and(|command| {
            interpreter_family(command) == Some(InterpreterFamily::Shell)
                && matches!(interpreter_mode(command), InterpreterMode::StdinScript)
        });
        let before = line
            .split_once("<<")
            .map(|(prefix, _)| prefix)
            .unwrap_or(line);
        if shell_owner {
            let quoted = body.join("\n").replace('\'', "'\"'\"'");
            output.push(format!("{before}-c '{quoted}'"));
        } else {
            output.push(before.trim_end().to_owned());
        }
        index = cursor + 1;
    }
    output.join("\n")
}
