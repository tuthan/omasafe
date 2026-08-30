//! Shell logical-source assembly: physical lines become whole logical
//! command units, with comments applied statefully and heredoc payloads
//! kept out of top-level command scanning.
//!
//! The `crate::detect` imports below read interpreter classification from
//! the parent module; that upward reference is temporary until command and
//! interpreter modeling extract into sibling modules (plan PR 3).

use super::lexer::{ShellToken, redirect_operator_at, tokenize};
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
            // A newline inside an open quote or backtick is body DATA: the
            // quoted text stays whole, and whatever reparses it (an eval or
            // `-c` body, a substitution interior) reads the newline as its
            // own statement separator. Inside a compound list a bare newline
            // separates statements; a grammar-required operator continuation
            // is whitespace instead.
            if in_single || in_double || in_backtick {
                text.push('\n');
            } else if token_depth > 0 && !trailing_pipeline_operator(&text) {
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

/// One heredoc redirection on a header line: the raw byte span covering the
/// operator and its delimiter word, plus `<<-`'s tab stripping. The
/// unquoted delimiter used for body-line matching comes from the token
/// stream, where quotes are already resolved.
struct HeredocRedirect {
    span: (usize, usize),
    strip_tabs: bool,
}

/// Every stdin heredoc redirection (`<<`/`<<-`) in one header line, in order.
/// The scan skips quoted regions, escapes, and balanced parentheses so a
/// quoted `<<`, a here-string `<<<`, or text inside `$( … )`/`( … )` never
/// matches, and applies `redirect_operator_at` — the same classifier the
/// lexer uses — so fd-prefixed forms (`2<<X`, other descriptors) stay data.
/// `None` when the raw scan and the token stream disagree: the line is then
/// left untouched rather than rewritten on a misunderstanding.
fn heredoc_redirects(line: &str, tokens: &[ShellToken]) -> Option<Vec<HeredocRedirect>> {
    let token_ops: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            matches!(token.operator(), Some("<<" | "<<-")).then_some(index)
        })
        .collect();
    if token_ops.is_empty() {
        return Some(Vec::new());
    }
    let bytes = line.as_bytes();
    let mut redirects = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
                i += 1;
            }
            b'`' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'`' {
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            _ => {
                if bytes[i] == b'(' {
                    i = skip_balanced_parens(bytes, i);
                    continue;
                }
                if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'(') {
                    i = skip_balanced_parens(bytes, i + 1);
                    continue;
                }
                if let Some((op, next)) = redirect_operator_at(bytes, i) {
                    if op == "<<" || op == "<<-" {
                        let (_, end) = delimiter_word_span(bytes, next)?;
                        redirects.push(HeredocRedirect {
                            span: (i, end),
                            strip_tabs: op == "<<-",
                        });
                        i = end;
                    } else {
                        i = next;
                    }
                    continue;
                }
                i += 1;
            }
        }
    }
    Some(redirects)
}

/// Just past the `)` matching the `(` at `open` (or the end of input when
/// the group never closes).
fn skip_balanced_parens(bytes: &[u8], open: usize) -> usize {
    let mut depth = 1usize;
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b'\'' | b'"' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        break;
                    }
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// The raw delimiter word just past a heredoc operator: quoted runs and
/// plain word bytes up to unquoted whitespace or an operator byte, so
/// `<<CODE|cat` keeps its pipeline tail. `None` when the line ends first.
fn delimiter_word_span(bytes: &[u8], mut i: usize) -> Option<(usize, usize)> {
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    let start = i;
    let mut quoted: Option<u8> = None;
    while i < bytes.len() {
        let byte = bytes[i];
        if let Some(quote) = quoted {
            if byte == b'\\' {
                i += 2;
                continue;
            }
            if byte == quote {
                quoted = None;
            }
            i += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => {
                quoted = Some(byte);
                i += 1;
            }
            b' ' | b'\t' | b'<' | b'>' | b'|' | b'&' | b';' | b'(' | b')' | b'\n' => break,
            _ => i += 1,
        }
    }
    (i > start).then_some((start, i))
}

/// Whether the heredoc redirected at token `op_index` is owned by a shell
/// interpreter running in stdin-script mode — the one case where the body is
/// executed code rather than data. The command containing the redirect runs
/// from the last top-level separator before it; wrapper chains count when
/// their wrapped interpreter reads stdin (`sudo sh <<X`).
fn heredoc_owner_is_shell_interpreter(tokens: &[ShellToken], op_index: usize) -> bool {
    let mut boundary = 0usize;
    let mut depth = 0i32;
    for (index, token) in tokens[..op_index].iter().enumerate() {
        match token.operator() {
            Some("(" | "{" | "((") => depth += 1,
            Some(")" | "}" | "))") => depth = (depth - 1).max(0),
            Some("|" | "|&" | ";" | "&&" | "||" | "&") if depth == 0 => boundary = index + 1,
            _ => {}
        }
    }
    segment_commands(&tokens[boundary..op_index])
        .iter()
        .any(|command| {
            interpreter_family(command) == Some(InterpreterFamily::Shell)
                && matches!(interpreter_mode(command), InterpreterMode::StdinScript)
        })
}

/// Remove heredoc payload lines from ordinary command scanning. A heredoc is
/// data unless its owning command is a shell interpreter; for that one case,
/// the body is rewritten into an equivalent `-c` body at the redirect's
/// position so the normal bounded shell walks can inspect the executed code.
/// Every heredoc on the line is handled — bodies are captured in
/// redirection order, each command owns its own redirects, and pipeline
/// tails survive the rewrite (`printf x | sh <<C | cat` keeps `| cat`).
/// Delimiters are tokenized, so quotes are removed only for comparison;
/// `<<-` accepts leading tabs on its terminator. Removed body and terminator
/// lines are replaced with blank lines so later units keep their physical
/// line numbers. Unterminated heredocs are left alone: treating the rest of
/// the file as data would hide live code after malformed input.
fn shell_source_without_heredoc_payloads(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut output = Vec::new();
    let mut index = 0usize;
    'lines: while index < lines.len() {
        let line = lines[index];
        let tokens = tokenize(line);
        let Some(redirects) =
            heredoc_redirects(line, &tokens).filter(|redirects| !redirects.is_empty())
        else {
            output.push(line.to_owned());
            index += 1;
            continue;
        };
        let token_ops: Vec<usize> = tokens
            .iter()
            .enumerate()
            .filter_map(|(token_index, token)| {
                matches!(token.operator(), Some("<<" | "<<-")).then_some(token_index)
            })
            .collect();
        let mut delimiters = Vec::with_capacity(redirects.len());
        for &op_index in &token_ops {
            let Some(word) = tokens.get(op_index + 1).and_then(ShellToken::word) else {
                output.push(line.to_owned());
                index += 1;
                continue 'lines;
            };
            delimiters.push(word.to_owned());
        }
        // Bodies are captured in redirection order: the first body follows
        // the header, each next body starts after the previous terminator.
        let mut bodies: Vec<Vec<&str>> = Vec::new();
        let mut cursor = index + 1;
        let mut terminated = true;
        for (k, redirect) in redirects.iter().enumerate() {
            let mut body = Vec::new();
            while cursor < lines.len() {
                let candidate = if redirect.strip_tabs {
                    lines[cursor].trim_start_matches('\t')
                } else {
                    lines[cursor]
                };
                if candidate == delimiters[k] {
                    break;
                }
                body.push(lines[cursor]);
                cursor += 1;
            }
            if cursor == lines.len() {
                terminated = false;
                break;
            }
            bodies.push(body);
            cursor += 1; // the terminator line
        }
        if !terminated {
            output.push(line.to_owned());
            index += 1;
            continue;
        }
        let owners: Vec<bool> = (0..redirects.len())
            .map(|k| heredoc_owner_is_shell_interpreter(&tokens, token_ops[k]))
            .collect();
        let mut header = String::new();
        let mut byte_cursor = 0usize;
        for (k, redirect) in redirects.iter().enumerate() {
            header.push_str(&line[byte_cursor..redirect.span.0]);
            byte_cursor = redirect.span.1;
            if owners[k]
                // Later redirects of the same command override earlier stdin,
                // so only the last adjacent one supplies the body.
                && token_ops
                    .get(k + 1)
                    .is_none_or(|next| *next != token_ops[k] + 2)
            {
                if !header.ends_with([' ', '\t', '(', ';', '&', '|']) {
                    header.push(' ');
                }
                let quoted = bodies[k].join("\n").replace('\'', "'\"'\"'");
                header.push_str(&format!("-c '{quoted}'"));
            }
        }
        header.push_str(&line[byte_cursor..]);
        // Blank lines stand in for the removed payload so physical line
        // numbers survive: however many lines the rewritten header itself
        // spans (embedded `-c` bodies contain newlines), the total matches
        // the original header + bodies + terminators.
        let header_lines = 1 + header.matches('\n').count();
        output.push(header);
        let original_span = 1 + bodies.iter().map(Vec::len).sum::<usize>() + redirects.len();
        for _ in 0..original_span.saturating_sub(header_lines) {
            output.push(String::new());
        }
        index += original_span;
    }
    output.join("\n")
}
