//! Shell logical-source assembly: physical lines become whole logical
//! command units, with comments applied statefully and heredoc payloads
//! kept out of top-level command scanning. Heredoc headers are classified
//! with their complete continued command — the owning word may sit on an
//! earlier line joined by an escaped newline, an open quote, or a trailing
//! operator — heredocs inside compound groups are captured, and later
//! heredocs of the same command override earlier ones by command
//! ownership. Bodies that execute out-of-band come back as isolated unit
//! groups: separately executed programs never share a parsing unit.
//!
//! This module depends only on the lexer. Heredoc ownership policy — what
//! the redirect-owning command does with the body — and the downstream
//! fate of a forwarded body are injected by the facade as classifiers, so
//! the source layer stays free of interpreter and command modeling.

use super::lexer::{ShellToken, redirect_operator_at, tokenize};

/// Internal line marker used for removed heredoc bodies and terminators. It
/// preserves physical line numbers without letting artificial blank lines
/// become whitespace in a continued pipeline or group during reassembly.
const HEREDOC_PLACEHOLDER: &str = "\0omasafe-heredoc-placeholder";

/// What the command owning a heredoc redirect does with the body.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::detect) enum HeredocOwner {
    /// A shell interpreter in stdin-script mode: the body is executed code.
    ExecutesStdin,
    /// A pure stdin-forwarding filter (`cat`, `tee`) with no file operand:
    /// the body flows to whatever consumes the owner's stdout downstream.
    ForwardsStdin,
    /// Data: the body is never executed.
    Data,
}

/// What becomes of a forwarded heredoc body downstream of its owner.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::detect) enum ForwardedBodyFate {
    /// No downstream stage executes the body: it is data, and removing its
    /// lines loses nothing.
    NotExecuted,
    /// The body executes as the `-c` body of the sink command whose head
    /// word ends at this byte offset in the tail.
    AttachAt(usize),
    /// The body executes VERBATIM as shell source through an indirect
    /// stdin-to-code consumer — a static `-c` body that consumes stdin
    /// (`sh -c sh`), a compound group's interpreter, `source /dev/stdin`,
    /// `eval "$(cat)"` — with no direct `-c` insertion point. Its lines
    /// stay in the source, so the analysis still sees the executed code
    /// instead of blanked-out text.
    ExecutedIndirectly,
    /// The body executes only after the consumer's own input processing:
    /// xargs quotes, word-splitting, and replacement decide which text
    /// runs, so these lines replace the body in the analysis (padded to
    /// the body's span).
    ExecutedAsInput(Vec<String>),
}

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
///
/// Heredoc bodies that execute out-of-band — verbatim through an indirect
/// stdin-to-code consumer, or as the consumer's processed input — are
/// returned as SEPARATE unit groups, one per body, each assembled in
/// isolation from its own text: bodies are independently executed
/// programs, so an unmatched quote or open group in one body can never
/// swallow another body's code, while every unit keeps its body lines'
/// physical numbers.
pub(in crate::detect) fn shell_logical_units(
    source: &str,
    classifies_owner: &dyn Fn(&[ShellToken], usize) -> HeredocOwner,
    forwarded_body_fate: &dyn Fn(&str, &str) -> ForwardedBodyFate,
) -> Vec<(u32, String)> {
    let (main, kept_bodies) =
        shell_source_without_heredoc_payloads(source, classifies_owner, forwarded_body_fate);
    let mut units = assemble_units(&main);
    for (start_line, body) in kept_bodies {
        units.extend(
            assemble_units(&body)
                .into_iter()
                .map(move |(line, text)| (start_line + line - 1, text)),
        );
    }
    units
}

/// The unit-assembly state machine over already-rewritten shell text:
/// physical lines are fed one at a time, and a completed logical unit is
/// returned whenever a line closes one. A unit continues across escaped
/// newlines (backslash-newline removed, no byte inserted), trailing
/// `|`/`|&`/`&&`/`||` operators, and open quotes, backticks, or `(`/`{`
/// groups, so a pipeline split over physical lines tokenizes whole
/// (`curl URL \` + `| sh`, `curl URL |` + `sh`). Comments are applied
/// statefully along the way — a `#` at a word boundary drops the rest of
/// its line, and a backslash-newline inside a comment never continues.
/// Body texts go through the same machine verbatim — a body is scanned
/// like any other shell source, with no heredoc rewriting of its own.
///
/// The heredoc pass drives a SECOND instance over the original source so
/// a heredoc header can be classified with its COMPLETE continued
/// command: the owning word may sit on an earlier line (`sh \` + `<<C`),
/// where the header line alone carries no command at all.
#[derive(Clone)]
struct UnitAssembler {
    /// Assembled text of the currently open unit (empty when closed).
    text: String,
    start_line: u32,
    open: bool,
    in_single: bool,
    in_double: bool,
    in_backtick: bool,
}

impl UnitAssembler {
    fn new() -> Self {
        Self {
            text: String::new(),
            start_line: 1,
            open: false,
            in_single: false,
            in_double: false,
            in_backtick: false,
        }
    }

    /// Feed one physical line (1-based `number`). Returns the completed
    /// unit when this line closes one.
    fn feed(&mut self, number: u32, raw_line: &str) -> Option<(u32, String)> {
        if !self.open {
            self.start_line = number;
        }
        let mut escaped_newline = false;
        let mut boundary = true; // a line start is a word boundary for `#`
        let mut characters = raw_line.chars().peekable();
        while let Some(character) = characters.next() {
            if self.in_single {
                if character == '\'' {
                    self.in_single = false;
                }
                self.text.push(character);
                boundary = false;
                continue;
            }
            if self.in_backtick {
                if character == '`' {
                    self.in_backtick = false;
                }
                self.text.push(character);
                boundary = false;
                continue;
            }
            if self.in_double {
                if character == '\\' {
                    match characters.next() {
                        // A backslash-newline continues even inside quotes.
                        None => escaped_newline = true,
                        Some(next) => {
                            self.text.push(character);
                            self.text.push(next);
                        }
                    }
                } else if character == '"' {
                    self.in_double = false;
                    self.text.push(character);
                } else {
                    self.text.push(character);
                }
                boundary = false;
                continue;
            }
            if character == '\\' {
                match characters.next() {
                    None => escaped_newline = true,
                    Some(next) => {
                        self.text.push(character);
                        self.text.push(next);
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
            self.text.push(character);
            boundary = matches!(character, ' ' | '\t' | ';' | '&' | '|' | '(');
            match character {
                '\'' => self.in_single = true,
                '"' => self.in_double = true,
                '`' => self.in_backtick = true,
                _ => {}
            }
        }
        if escaped_newline {
            self.open = true; // the backslash-newline is removed: join directly
            return None;
        }
        // The lexer, rather than raw bytes, decides whether a compound list
        // remains open. In particular `foo{` and an escaped `\\|` are words,
        // not group/pipeline syntax.
        let token_depth =
            tokenize(&self.text)
                .iter()
                .fold(0i32, |depth, token| match token.operator() {
                    Some("(" | "{" | "((") => depth + 1,
                    Some(")" | "}" | "))") => (depth - 1).max(0),
                    _ => depth,
                });
        self.open = self.in_single
            || self.in_double
            || self.in_backtick
            || token_depth > 0
            || trailing_pipeline_operator(&self.text);
        if self.open {
            // A newline inside an open quote or backtick is body DATA: the
            // quoted text stays whole, and whatever reparses it (an eval or
            // `-c` body, a substitution interior) reads the newline as its
            // own statement separator. Inside a compound list a bare newline
            // separates statements; a grammar-required operator continuation
            // is whitespace instead.
            if self.in_single || self.in_double || self.in_backtick {
                self.text.push('\n');
            } else if token_depth > 0 && !trailing_pipeline_operator(&self.text) {
                self.text.push(';');
            } else {
                self.text.push(' ');
            }
            None
        } else if !self.text.trim().is_empty() {
            let assembled = std::mem::take(&mut self.text);
            self.in_single = false;
            self.in_double = false;
            self.in_backtick = false;
            Some((self.start_line, assembled.trim_end().to_owned()))
        } else {
            None
        }
    }

    /// Flush a trailing open unit at the end of the source.
    fn finish(self) -> Vec<(u32, String)> {
        if self.text.trim().is_empty() {
            Vec::new()
        } else {
            vec![(self.start_line, self.text.trim_end().to_owned())]
        }
    }
}

fn assemble_units(source: &str) -> Vec<(u32, String)> {
    let mut assembler = UnitAssembler::new();
    let mut units = Vec::new();
    for (index, raw_line) in source.lines().enumerate() {
        if raw_line == HEREDOC_PLACEHOLDER {
            continue;
        }
        if let Some(unit) = assembler.feed(index as u32 + 1, raw_line) {
            units.push(unit);
        }
    }
    units.extend(assembler.finish());
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

/// One heredoc redirection of a whole logical unit: which physical line of
/// the unit carries it (0-based from the unit's first line), the raw span
/// within that line, `<<-`'s tab stripping, and the tokenized delimiter
/// word used for body-line matching.
struct UnitHeredoc {
    line: usize,
    span: (usize, usize),
    strip_tabs: bool,
    delimiter: String,
}

/// Every stdin heredoc redirection (`<<`/`<<-`) in one header line, in order.
/// The scan skips quoted regions, escapes, and command-substitution
/// interiors so a quoted `<<`, a here-string `<<<`, or text inside
/// `$( … )` never matches, and applies `redirect_operator_at` — the same
/// classifier the lexer uses — so fd-prefixed forms (`2<<X`, other
/// descriptors) stay data. Compound groups are NOT skipped: a heredoc of
/// a grouped command is a real heredoc (`(cat <<C)` reads its body as
/// data, `(sh <<C)` executes it), and the caller's raw-scan/token
/// agreement check covers anything the two views disagree on. `None` when
/// the raw scan and the token stream disagree: the line is then left
/// untouched rather than rewritten on a misunderstanding.
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

/// Whether the newline ending `line` reads a pending heredoc's body: bash
/// collects bodies at the first newline that is neither escaped nor inside
/// quotes/backticks — a trailing pipeline operator or an open compound
/// group does NOT postpone it (`cat <<C |` reads the next line as body
/// data, and the pipeline's next stage follows the terminator). A `#`
/// comment ends the line, including any trailing backslash.
fn newline_terminates_heredoc_header(line: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    let mut boundary = true; // a line start is a word boundary for `#`
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        if in_single {
            if character == '\'' {
                in_single = false;
            }
            boundary = false;
            continue;
        }
        if in_backtick {
            if character == '`' {
                in_backtick = false;
            }
            boundary = false;
            continue;
        }
        if in_double {
            if character == '\\' {
                characters.next();
            } else if character == '"' {
                in_double = false;
            }
            boundary = false;
            continue;
        }
        match character {
            '\\' => {
                if characters.next().is_none() {
                    return false; // escaped newline: the body waits
                }
                boundary = false;
            }
            '#' if boundary => return true, // a comment ends the line
            _ => {
                boundary = matches!(character, ' ' | '\t' | ';' | '&' | '|' | '(');
                match character {
                    '\'' => in_single = true,
                    '"' => in_double = true,
                    '`' => in_backtick = true,
                    _ => {}
                }
            }
        }
    }
    !in_single && !in_double && !in_backtick
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

/// Remove heredoc payload lines from ordinary command scanning. A heredoc is
/// data unless its owning command is a shell interpreter; for that one case,
/// the body is rewritten into an equivalent `-c` body at the redirect's
/// position so the normal bounded shell walks can inspect the executed code.
/// Every heredoc of the whole logical command is handled — bodies are
/// captured in redirection order, each command owns its own redirects, and
/// pipeline tails survive the rewrite (`printf x | sh <<C | cat` keeps
/// `| cat`). Delimiters are tokenized, so quotes are removed only for
/// comparison; `<<-` accepts leading tabs on its terminator.
///
/// Ownership AND body placement are decided against the COMPLETE continued
/// header, not the bare line carrying the operator: a heredoc operator may
/// sit on its own physical line while the owning word sits on an earlier
/// one joined by an escaped newline or an open quote (`sh \` + `<<C`), and
/// the body begins at the header's first newline that is neither escaped
/// nor inside quotes — `cat <<A | \` + `cat <<B` reads both bodies after
/// the second line, later header lines can carry heredocs of their own
/// (`sh <<A; \` + `sh <<B`), and a trailing `|` or an open compound group
/// does NOT postpone the body (`cat <<C |` reads the next line as body
/// data while the pipeline's next stage follows the terminator). The
/// pipeline tail the body fate walks spans that post-body continuation.
///
/// Later heredocs of the SAME command override earlier stdin, so only each
/// command's last heredoc supplies its body — decided by command ownership
/// across list and pipeline separators, not token adjacency
/// (`sh <<A -x <<B` still runs B, not A).
///
/// Bodies that execute out-of-band — verbatim through an indirect
/// stdin-to-code consumer, or as the consumer's processed input — are
/// returned SEPARATELY (with the body's first physical line) instead of
/// staying in the main stream, so independently executed programs never
/// share a parsing unit. Removed body and terminator lines are replaced
/// with blank lines so later units keep their physical line numbers.
/// Unterminated heredocs are left alone: treating the rest of the file as
/// data would hide live code after malformed input. A raw-scan/token
/// disagreement on any line of the unit likewise leaves the whole unit
/// alone.
fn shell_source_without_heredoc_payloads(
    source: &str,
    classifies_owner: &dyn Fn(&[ShellToken], usize) -> HeredocOwner,
    forwarded_body_fate: &dyn Fn(&str, &str) -> ForwardedBodyFate,
) -> (String, Vec<(u32, String)>) {
    let lines: Vec<&str> = source.lines().collect();
    let mut output = Vec::new();
    let mut kept_bodies: Vec<(u32, String)> = Vec::new();
    let mut index = 0usize;
    // Logical-unit state over the EMITTED text — original lines and
    // rewritten headers, never heredoc bodies — so classification sees the
    // same continued command the final assembly will.
    let mut context = UnitAssembler::new();
    'lines: while index < lines.len() {
        let line = lines[index];
        let tokens = tokenize(line);
        if !heredoc_redirects(line, &tokens).is_some_and(|scan| !scan.is_empty()) {
            output.push(line.to_owned());
            context.feed(index as u32 + 1, line);
            index += 1;
            continue;
        }
        // A heredoc body follows the redirection-bearing command's first
        // newline that is neither escaped nor inside quotes — a trailing
        // pipeline operator or an open compound group does NOT postpone
        // it, and the command's continuation (the pipeline stage, the
        // group's closing parenthesis) follows the terminator line.
        let mut boundary = index;
        while !newline_terminates_heredoc_header(lines[boundary]) {
            if boundary + 1 == lines.len() {
                // EOF inside an escaped/quoted header: the command never
                // reaches its newline, so no body follows — leave the rest
                // of the file alone.
                for &rest in lines[index..].iter() {
                    output.push(rest.to_owned());
                    context.feed(index as u32 + 1, rest);
                    index += 1;
                }
                continue 'lines;
            }
            boundary += 1;
        }
        // Every heredoc lexed before that newline, in redirection order
        // across the header's physical lines. The rewrite aligns the raw
        // scan with the token stream one to one on EVERY header line;
        // anything else leaves the whole header alone.
        let mut unit_redirects: Vec<UnitHeredoc> = Vec::new();
        for (offset, line_index) in (index..=boundary).enumerate() {
            let unit_line = lines[line_index];
            let unit_tokens = tokenize(unit_line);
            let unit_ops: Vec<usize> = unit_tokens
                .iter()
                .enumerate()
                .filter_map(|(token_index, token)| {
                    matches!(token.operator(), Some("<<" | "<<-")).then_some(token_index)
                })
                .collect();
            let Some(unit_scan) = heredoc_redirects(unit_line, &unit_tokens)
                .filter(|scan| scan.len() == unit_ops.len())
            else {
                for (offset, &rest) in lines[index..=boundary].iter().enumerate() {
                    output.push(rest.to_owned());
                    context.feed(index as u32 + 1 + offset as u32, rest);
                }
                index = boundary + 1;
                continue 'lines;
            };
            for (&token_index, redirect) in unit_ops.iter().zip(&unit_scan) {
                let Some(word) = unit_tokens.get(token_index + 1).and_then(ShellToken::word) else {
                    for (offset, &rest) in lines[index..=boundary].iter().enumerate() {
                        output.push(rest.to_owned());
                        context.feed(index as u32 + 1 + offset as u32, rest);
                    }
                    index = boundary + 1;
                    continue 'lines;
                };
                unit_redirects.push(UnitHeredoc {
                    line: offset,
                    span: redirect.span,
                    strip_tabs: redirect.strip_tabs,
                    delimiter: word.to_owned(),
                });
            }
        }
        // Bodies are captured in redirection order, starting after the
        // header's last line: the first body follows the command's
        // terminating newline, each next body starts after the previous
        // terminator.
        let mut bodies: Vec<Vec<&str>> = Vec::new();
        let mut cursor = boundary + 1;
        let mut terminated = true;
        for redirect in &unit_redirects {
            let mut body = Vec::new();
            while cursor < lines.len() {
                let candidate = if redirect.strip_tabs {
                    lines[cursor].trim_start_matches('\t')
                } else {
                    lines[cursor]
                };
                if candidate == redirect.delimiter {
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
            for (offset, &rest) in lines[index..=boundary].iter().enumerate() {
                output.push(rest.to_owned());
                context.feed(index as u32 + 1 + offset as u32, rest);
            }
            index = boundary + 1;
            continue;
        }
        // Ownership is classified over the JOINED continued header: probe
        // the unit state with the header's raw lines, then take the batch's
        // heredoc operators from the joined stream's final ones (the prefix
        // carries none — earlier heredocs were rewritten away). The same
        // probe then walks the body placeholders and the command's
        // post-body continuation to build the pipeline tail: bash resumes
        // the command after the last terminator, so a trailing `|` on the
        // header binds the post-body stage (`cat <<C |` + body + `C` +
        // `xargs sh -c` runs the body through xargs). The placeholders
        // contribute only the join separators, exactly like the blanked
        // emission below.
        let mut probe = context.clone();
        let mut line_base = vec![0usize; boundary - index + 1];
        let mut header_text: Option<String> = None;
        let mut full_text: Option<String> = None;
        for (offset, line_index) in (index..=boundary).enumerate() {
            line_base[offset] = probe.text.len();
            if let Some((_, text)) = probe.feed(line_index as u32 + 1, lines[line_index]) {
                header_text = Some(text.clone());
                full_text = Some(text);
            }
        }
        if probe.open {
            for _ in 0..(bodies.iter().map(Vec::len).sum::<usize>() + unit_redirects.len()) {
                if let Some((_, text)) = probe.feed(0, "") {
                    full_text = Some(text);
                }
                if !probe.open {
                    break;
                }
            }
            let mut resume =
                boundary + 1 + bodies.iter().map(Vec::len).sum::<usize>() + unit_redirects.len();
            while probe.open && resume < lines.len() {
                if let Some((_, text)) = probe.feed(resume as u32 + 1, lines[resume]) {
                    full_text = Some(text);
                }
                resume += 1;
            }
        }
        // A header that ends with a trailing operator or an open group only
        // completes after the post-heredoc continuation has been probed. In
        // that case `probe.text` is empty after `feed` returns the completed
        // unit, so classify the completed text captured in `full_text`.
        let context_text = header_text
            .or(full_text.clone())
            .unwrap_or_else(|| probe.text.clone());
        let tail_text = full_text.unwrap_or_else(|| probe.text.clone());
        let joined = tokenize(&context_text);
        let joined_ops: Vec<usize> = joined
            .iter()
            .enumerate()
            .filter_map(|(token_index, token)| {
                matches!(token.operator(), Some("<<" | "<<-")).then_some(token_index)
            })
            .collect();
        let Some(base) = joined_ops.len().checked_sub(unit_redirects.len()) else {
            for (offset, &rest) in lines[index..=boundary].iter().enumerate() {
                output.push(rest.to_owned());
                context.feed(index as u32 + 1 + offset as u32, rest);
            }
            index = boundary + 1;
            continue;
        };
        let owners: Vec<HeredocOwner> = (0..unit_redirects.len())
            .map(|k| classifies_owner(&joined, joined_ops[base + k]))
            .collect();
        let ordinals = command_ordinals(&joined, &joined_ops);
        let command_of = &ordinals[base..];
        // Dispositions decided BEFORE the header is built: `-c` attaches
        // embed the body into the header and grow it over the span's early
        // lines; every other body — data or out-of-band executed — is
        // blanked, and the blank sections absorb the header's surplus
        // earliest first, so every later unit keeps its physical line.
        enum BodyDisposition {
            /// Data, overridden stdin, or executed out-of-band: blank
            /// lines stand in.
            Blank,
            /// The body attaches as a `-c` body at this byte offset in the
            /// owner's tail (the offset is relative to the tail start;
            /// owner-executed bodies attach at the header's current end).
            Attach(Option<usize>),
        }
        // The first physical line of each body (1-based): the line after
        // the header's last line plus each earlier body's lines and
        // terminators.
        let body_start = |k: usize| -> u32 {
            let mut line = boundary as u32 + 2;
            for earlier in bodies.iter().take(k) {
                line += earlier.len() as u32 + 1;
            }
            line
        };
        let mut dispositions: Vec<BodyDisposition> = (0..unit_redirects.len())
            .map(|_| BodyDisposition::Blank)
            .collect();
        for (k, unit_redirect) in unit_redirects.iter().enumerate() {
            // Overridden by a later heredoc of the same command.
            if (k + 1..unit_redirects.len()).any(|later| command_of[later] == command_of[k]) {
                continue;
            }
            let body = bodies[k].join("\n");
            dispositions[k] = match owners[k] {
                HeredocOwner::ExecutesStdin => BodyDisposition::Attach(None),
                HeredocOwner::ForwardsStdin => {
                    // The tail starts at the redirect inside the JOINED
                    // header-plus-continuation text, so it reaches the
                    // pipeline stage that follows the bodies.
                    let tail_at = line_base[unit_redirect.line] + unit_redirect.span.1;
                    let tail = tail_text.get(tail_at..).unwrap_or_default();
                    match forwarded_body_fate(tail, &body) {
                        ForwardedBodyFate::AttachAt(attach_offset) => {
                            let owner_line = lines[index + unit_redirect.line];
                            if unit_redirect.span.1 + attach_offset <= owner_line.len() {
                                BodyDisposition::Attach(Some(attach_offset))
                            } else {
                                // The attach point sits on a physical line
                                // after the blanked bodies (`cat <<C |` +
                                // body + `C` + `sh`): the body executes out
                                // of band instead of splicing across the
                                // span.
                                kept_bodies.push((body_start(k), body));
                                BodyDisposition::Blank
                            }
                        }
                        // Out-of-band executions come back as isolated unit
                        // groups: the body is its own program, analyzed from
                        // its own text at its own lines — verbatim for an
                        // indirect stdin-to-code consumer, and as the
                        // consumer's processed input for xargs models.
                        ForwardedBodyFate::ExecutedIndirectly => {
                            kept_bodies.push((body_start(k), body));
                            BodyDisposition::Blank
                        }
                        ForwardedBodyFate::ExecutedAsInput(lines) => {
                            kept_bodies.push((body_start(k), lines.join("\n")));
                            BodyDisposition::Blank
                        }
                        ForwardedBodyFate::NotExecuted => BodyDisposition::Blank,
                    }
                }
                HeredocOwner::Data => BodyDisposition::Blank,
            };
        }
        // Rewrite each header line in place: every heredoc of that line is
        // spliced per its disposition, so a multi-line command keeps its
        // header text on the lines it came from.
        let unit_span = boundary - index + 1;
        let mut rewritten: Vec<String> = Vec::with_capacity(unit_span);
        for offset in 0..unit_span {
            let unit_line = lines[index + offset];
            let mut header = String::new();
            let mut byte_cursor = 0usize;
            for (k, unit_redirect) in unit_redirects.iter().enumerate() {
                if unit_redirect.line != offset {
                    continue;
                }
                header.push_str(&unit_line[byte_cursor..unit_redirect.span.0]);
                byte_cursor = unit_redirect.span.1;
                let BodyDisposition::Attach(attach) = &dispositions[k] else {
                    // Removing `<<DELIM` from `cat <<DELIM | ...` leaves
                    // whitespace on both sides of the span. Keep one copy so
                    // the resumed command has the same readable shape as
                    // the original pipeline.
                    if boundary == index
                        && header.ends_with([' ', '\t'])
                        && unit_line[byte_cursor..].starts_with([' ', '\t'])
                    {
                        header.pop();
                    }
                    continue; // kept and blanked bodies carry no header text
                };
                if !header.ends_with([' ', '\t', '(', ';', '&', '|']) {
                    header.push(' ');
                }
                let quoted = bodies[k].join("\n").replace('\'', "'\"'\"'");
                match attach {
                    // A forwarding filter passes the body to its downstream
                    // consumer (`cat <<C | sh` runs the body, exactly like
                    // `sh -c '…'`); the classifier walks the whole pipeline
                    // tail with the interpreter, wrapper, redirect, and
                    // forwarding models and gives the attach point just past
                    // the consumer's head word.
                    Some(attach_offset) => {
                        let end = byte_cursor + attach_offset;
                        header.push_str(&unit_line[byte_cursor..end]);
                        header.push_str(&format!(" -c '{quoted}'"));
                        byte_cursor = end;
                    }
                    // The owner itself executes the body as stdin.
                    None => header.push_str(&format!("-c '{quoted}'")),
                }
            }
            header.push_str(&unit_line[byte_cursor..]);
            rewritten.push(header);
        }
        // Reproduce the original span line for line: every body section is
        // blanked (out-of-band bodies analyze from their own unit groups),
        // and rewritten headers grown by attached `-c` bodies span extra
        // lines that the blank sections absorb earliest first — so later
        // units keep their physical line numbers whatever mix of fates the
        // unit had.
        let original_span =
            unit_span + bodies.iter().map(Vec::len).sum::<usize>() + unit_redirects.len();
        let mut surplus = rewritten
            .iter()
            .map(|header| 1 + header.matches('\n').count())
            .sum::<usize>()
            - unit_span;
        for (offset, header) in rewritten.into_iter().enumerate() {
            // The unit state continues from the REWRITTEN headers: their
            // trailing bytes match the original tails, and attached `-c`
            // bodies carry balanced quotes, so later continuations join the
            // same command.
            context.feed(index as u32 + 1 + offset as u32, &header);
            output.push(header);
        }
        // A same-line header (including the new trailing-operator/group
        // boundary) can skip artificial lines during reassembly. For a
        // backslash-continued header, retain the historical blank-line
        // separators: they are part of the continuation's whitespace shape.
        let placeholder = if boundary == index {
            HEREDOC_PLACEHOLDER.to_owned()
        } else {
            String::new()
        };
        for body in bodies.iter() {
            let eaten = surplus.min(body.len());
            surplus -= eaten;
            output.extend(std::iter::repeat_n(placeholder.clone(), body.len() - eaten));
            let eaten = surplus.min(1);
            surplus -= eaten;
            output.extend(std::iter::repeat_n(placeholder.clone(), 1 - eaten)); // the terminator
        }
        index += original_span;
    }
    (output.join("\n"), kept_bodies)
}

/// Pipeline-segment ordinal of each heredoc operator on the header line:
/// every list separator (`;`, `&&`, `||`, `&`, `|`, `|&`) starts a new
/// command at any group depth — inside a compound group the group's own
/// statements are separate commands — so a heredoc is overridden only by a
/// later heredoc of the same command.
fn command_ordinals(tokens: &[ShellToken], ops: &[usize]) -> Vec<usize> {
    let mut ordinals = Vec::with_capacity(ops.len());
    let mut ordinal = 0usize;
    let mut depth = 0i32;
    let mut next = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if next < ops.len() && ops[next] == index {
            ordinals.push(ordinal);
            next += 1;
        }
        match token.operator() {
            Some("(" | "{" | "((") => depth += 1,
            Some(")" | "}" | "))") => depth = (depth - 1).max(0),
            Some(";" | "&&" | "||" | "&" | "|" | "|&") => ordinal += 1,
            _ => {}
        }
    }
    ordinals
}
