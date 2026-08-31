//! The GNU xargs input model.
//!
//! Extracted from `detect.rs` (plan A4): where an xargs invocation puts its
//! input — option area, replacement placeholder, batch and delimiter modes,
//! and item splitting — so a piped or heredoc-fed body is only reported as
//! executed when it really reaches the wrapped command's code positions.

use super::command::{ScriptCommand, command_basename, segment_commands, skip_command_prefixes};
use super::interpreter::{
    InterpreterFamily, command_is_interpreter, interpreter_family, separate_cluster_value,
};
use super::lexer::{ShellToken, tokenize};
use super::source::ForwardedBodyFate;
use super::syntax::{conditional_statements, pipeline_segments};

/// `xargs` appends its input to the wrapped command's argv. The input
/// reaches executed code when the wrapped shell invocation has no static
/// place to put it: a `-c` mode without a body (the input becomes the
/// body), a body that flows input through positional parameters or the
/// `-I` replacement placeholder into command position, a stdin operand
/// (`-`), or no operand at all (the input becomes the executed script
/// file). A static script operand pins the executed file, so a later `-c`
/// spelling is its argument, not a mode (`xargs sh local-script -c`).
pub(in crate::detect) fn xargs_feeds_stdin_code(command: &ScriptCommand) -> bool {
    let Some(wrapped) = xargs_wrapped_command(command) else {
        return false;
    };
    if !xargs_option_area_is_valid(command, wrapped) {
        return false;
    }
    let placeholder = xargs_placeholder(command, wrapped);
    if let Some(head) = command.args.get(wrapped)
        && placeholder
            .as_deref()
            .is_some_and(|mark| head.contains(mark))
    {
        return true; // the input word IS the executed program
    }
    let wrapped_command = ScriptCommand {
        head: command_basename(command.args[wrapped]),
        args: command.args[wrapped + 1..].to_vec(),
        arg_dynamic: command.arg_dynamic[wrapped + 1..].to_vec(),
    };
    if interpreter_family(&wrapped_command) != Some(InterpreterFamily::Shell) {
        return false;
    }
    let mut c_body: Option<&str> = None;
    let mut c_requested = false;
    let mut index = 0usize;
    while let Some(arg) = wrapped_command.args.get(index) {
        if *arg == "--" {
            // The first operand after `--` is the executed script file.
            return match wrapped_command.args.get(index + 1) {
                None => true, // the input fills the script position
                Some(operand) => operand_is_input_code(operand, placeholder.as_deref()),
            };
        }
        if !arg.starts_with('-') {
            if *arg == "-" {
                return true; // stdin operand: the shell executes the pipe
            }
            // First non-option operand: the executed script file. With a
            // pending `-c` whose body it is, the body decides instead.
            if c_requested {
                return match c_body {
                    None => true,
                    Some(body) => body_is_input_code(body, placeholder.as_deref()),
                };
            }
            return operand_is_input_code(arg, placeholder.as_deref());
        }
        if is_short_option(arg, 'c') {
            c_requested = true;
            c_body = separate_cluster_value(&wrapped_command, index);
        }
        index += 1;
    }
    if c_requested {
        // Body-less `-c`: the input word becomes the command body.
        return match c_body {
            None => true,
            Some(body) => body_is_input_code(body, placeholder.as_deref()),
        };
    }
    // No `-c`, no operand: the input word becomes the executed script file.
    true
}

/// A GNU xargs count: `strtol`-style — an optional leading `+`, leading
/// zeros, then decimal digits, so `01` and `+1` are both 1. Anything else
/// is a usage error at runtime, and a failed xargs run executes no input.
fn xargs_count(value: &str) -> Option<usize> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<usize>().ok()
}

/// The `-I`/`--replace` placeholder of this xargs invocation, when one
/// survives to runtime: xargs substitutes it with each input item wherever
/// it appears in the initial arguments. GNU xargs warns and honors the
/// LAST of `-I`/`-L`/`-n`, so a later batch option overrides replacement
/// (`-I{} -n2` drops it) and a later `-I` restores it — except that
/// `-n1` in every numeric spelling (`-n01`, `--max-args=+1`) preserves
/// replacement, since one whole item per invocation is what `-I` already
/// means. Valued options consume their separate value word even when it
/// LOOKS like an option (`xargs -I -n` takes `-n` as the replstr); GNU
/// `--replace` takes its value only after `=`, the bare form defaulting
/// to `{}`.
fn xargs_placeholder(command: &ScriptCommand, wrapped: usize) -> Option<String> {
    let mut placeholder: Option<String> = None;
    let mut index = 0usize;
    while index < wrapped {
        let arg = &command.args[index];
        let mut advance = 1usize;
        if let Some(long) = arg.strip_prefix("--") {
            let (name, glued) = long
                .split_once('=')
                .map(|(name, value)| (name, Some(value)))
                .unwrap_or((long, None));
            match name {
                "replace" => {
                    // GNU `--replace[=STR]` never consumes the next word.
                    placeholder = match glued {
                        // `--replace=` replaces nothing.
                        Some("") => None,
                        Some(value) => Some(value.to_owned()),
                        None => Some("{}".to_owned()),
                    };
                }
                "max-args" => {
                    // Replacement mode specifically survives a numeric one
                    // (`xargs -I{} -n01 sh -c '{}'` runs the input); any
                    // other count, and `-L` at every count, drops it.
                    let count = glued.map_or_else(|| command.args.get(index + 1).copied(), Some);
                    if xargs_count(count.unwrap_or_default()) != Some(1) {
                        placeholder = None;
                    }
                    if glued.is_none() {
                        advance = 2; // the separate count word
                    }
                }
                "max-lines" => placeholder = None,
                _ => {}
            }
        } else if arg.len() > 1 && arg.starts_with('-') {
            let flags = &arg[1..];
            match flags.chars().next() {
                Some('I') => {
                    placeholder = if flags.len() > 1 {
                        Some(flags[1..].to_owned())
                    } else {
                        // The separate replacement word is consumed even
                        // when it looks like an option.
                        advance = 2;
                        command.args.get(index + 1).map(|value| value.to_string())
                    };
                }
                Some(flag @ ('n' | 'L')) => {
                    let count = if flags.len() > 1 {
                        Some(&flags[1..])
                    } else {
                        advance = 2;
                        command.args.get(index + 1).copied()
                    };
                    if !(flag == 'n' && xargs_count(count.unwrap_or_default()) == Some(1)) {
                        placeholder = None;
                    }
                }
                _ => {}
            }
        }
        index += advance;
    }
    placeholder
}

/// The fate of a heredoc body fed through an `xargs` sink. xargs parses its
/// input into items (honoring quotes and backslashes; line-based under
/// `-I`/`-L`, whole-text under `-0`/`-d`) and appends the items to the
/// wrapped command's argv — so the body text does NOT run verbatim as shell
/// source. The existing option, replacement, and input-field model decides
/// where the items land: a body-less `-c` gives the FIRST item of every
/// invocation batch its own command body (the batch's remaining items are
/// positional parameters), a `-I` placeholder reaching a code position
/// takes every item, and every other position — the executed script file,
/// data operands — never runs the body text.
pub(in crate::detect) fn xargs_body_fate(
    command: &ScriptCommand,
    body: &str,
) -> super::source::ForwardedBodyFate {
    let Some(landing) = xargs_landing(command) else {
        return ForwardedBodyFate::NotExecuted;
    };
    // The items that execute as `-c` bodies, each with the body line it
    // starts on.
    let executed: Vec<XargsItem> = match landing.sink {
        // `-I`: every input line replaces the placeholder and executes.
        XargsSink::PlaceholderCode => xargs_line_items(body),
        XargsSink::BatchBodies => match &landing.items {
            // Default: the whole input is one invocation, so only its
            // first item is the `-c` body; `-n N` repeats the invocation
            // per N items, and every batch's first item executes.
            XargsItems::Word { per_invocation } => {
                let items = xargs_word_items(body);
                match per_invocation {
                    Some(n) => items
                        .chunks(*n)
                        .filter_map(|batch| batch.first().cloned())
                        .collect(),
                    None => items.into_iter().next().into_iter().collect(),
                }
            }
            // `-L N`: N logical lines per invocation, each line still
            // word-split — the invocation's first item is the body. `-I`
            // (one whole line per invocation) is the N = 1 no-split case.
            XargsItems::Lines {
                split,
                per_invocation,
            } => xargs_logical_line_groups(body)
                .chunks(*per_invocation)
                .filter_map(|batch| {
                    // The batch's first word item — blank lines in the
                    // batch contribute none, so later lines can still
                    // start the invocation.
                    let mut first: Option<XargsItem> = None;
                    'batch: for group in batch {
                        for (line, text) in group {
                            let items: Vec<XargsItem> = if *split {
                                xargs_word_items(text)
                            } else {
                                vec![XargsItem {
                                    line: 0,
                                    text: xargs_strip_item_quotes(text),
                                }]
                            };
                            if let Some(mut item) = items.into_iter().next() {
                                item.line = *line;
                                first = Some(item);
                                break 'batch;
                            }
                        }
                    }
                    first
                })
                .collect(),
            // `-0`/`-d`: no quote processing — the whole input is one
            // item, or is split on the delimiter, and `-n N` still groups
            // the items into repeated invocations with every batch's
            // first item as the `-c` body.
            XargsItems::Whole {
                delimiter,
                per_invocation,
            } => {
                let mut line = 0usize;
                let items: Vec<XargsItem> = match delimiter.as_deref().filter(|d| !d.is_empty()) {
                    Some(delimiter) => body
                        .split(delimiter)
                        .map(|part| {
                            let item = XargsItem {
                                line,
                                text: part.to_owned(),
                            };
                            line += part.matches('\n').count();
                            item
                        })
                        .collect(),
                    None => vec![XargsItem {
                        line: 0,
                        text: body.to_owned(),
                    }],
                };
                match per_invocation {
                    Some(n) => items
                        .chunks(*n)
                        .filter_map(|batch| batch.first().cloned())
                        .collect(),
                    None => items.into_iter().next().into_iter().collect(),
                }
            }
        },
    };
    if executed.is_empty() {
        return ForwardedBodyFate::NotExecuted;
    }
    // Separate invocations run as separate statements; items starting on
    // the same body line share that line, others keep their own.
    let mut out = vec![String::new(); body.lines().count()];
    for item in executed {
        if let Some(slot) = out.get_mut(item.line) {
            if slot.is_empty() {
                *slot = item.text;
            } else {
                slot.push_str("; ");
                slot.push_str(&item.text);
            }
        }
    }
    ForwardedBodyFate::ExecutedAsInput(out)
}

/// Where an xargs invocation puts its input, decided on its option area
/// and the wrapped command's argv. `None` when the input never becomes
/// code: a script operand pins the executed file, a static `-c` body
/// without a placeholder treats items as positional parameters, and `-a`
/// reads items from a file instead of stdin.
fn xargs_landing(command: &ScriptCommand) -> Option<XargsLanding> {
    let wrapped = xargs_wrapped_command(command)?;
    if !xargs_option_area_is_valid(command, wrapped) {
        return None;
    }
    let placeholder = xargs_placeholder(command, wrapped);
    let mut landing = XargsLanding {
        sink: XargsSink::BatchBodies,
        items: XargsItems::Word {
            per_invocation: None,
        },
    };
    let mut index = 0usize;
    while index < wrapped {
        let arg = command.args[index];
        let mut advance = 1usize;
        if let Some(long) = arg.strip_prefix("--") {
            let (name, glued) = long
                .split_once('=')
                .map(|(name, value)| (name, Some(value)))
                .unwrap_or((long, None));
            let value = || {
                glued
                    .map(str::to_owned)
                    .or_else(|| command.args.get(index + 1).map(|v| v.to_string()))
            };
            match name {
                "null" => landing.set_delimited(None),
                "delimiter" => {
                    landing.set_delimited(value());
                    if glued.is_none() {
                        advance = 2;
                    }
                }
                // GNU `--replace[=STR]` takes its value only after `=`:
                // the bare form defaults to `{}` and the next word is the
                // wrapped command.
                "replace" => {
                    landing.items = XargsItems::Lines {
                        split: false,
                        per_invocation: 1,
                    };
                }
                "max-args" => {
                    if let Some(n) = value() {
                        landing.set_word_batch(&n);
                    }
                    if glued.is_none() {
                        advance = 2;
                    }
                }
                "max-lines" => {
                    // GNU `--max-lines[=N]` takes its value only after `=`;
                    // the bare form means one line and never consumes the
                    // next word.
                    landing.set_line_batch(glued.unwrap_or("1"));
                }
                "arg-file" => return None, // items come from a file, not stdin
                _ => {}
            }
        } else if arg.len() > 1 && arg.starts_with('-') {
            let flags = &arg[1..];
            match flags.chars().next() {
                Some('0') => landing.set_delimited(None),
                Some('d') => {
                    if let Some(glued) = flags.get(1..).filter(|rest| !rest.is_empty()) {
                        landing.set_delimited(Some(glued.to_owned()));
                    } else {
                        landing.set_delimited(command.args.get(index + 1).map(|v| v.to_string()));
                        advance = 2;
                    }
                }
                Some('I') => {
                    landing.items = XargsItems::Lines {
                        split: false,
                        per_invocation: 1,
                    };
                    if flags.len() == 1 {
                        advance = 2; // the separate placeholder word
                    }
                }
                Some('L') | Some('n') => {
                    let count = if flags.len() == 1 {
                        advance = 2;
                        command.args.get(index + 1).map(|value| &**value)
                    } else {
                        Some(&flags[1..])
                    };
                    if let Some(count) = count {
                        if flags.starts_with('L') {
                            landing.set_line_batch(count);
                        } else {
                            landing.set_word_batch(count);
                        }
                    }
                }
                Some('a') => return None, // items come from a file, not stdin
                _ => {}
            }
        }
        index += advance;
    }
    // The wrapped command must be a shell interpreter, and the input must
    // reach a code position: a body-less `-c` (the first item becomes the
    // body) or a `-I` placeholder inside the static `-c` body.
    let wrapped_command = ScriptCommand {
        head: command_basename(command.args[wrapped]),
        args: command.args[wrapped + 1..].to_vec(),
        arg_dynamic: command.arg_dynamic[wrapped + 1..].to_vec(),
    };
    if interpreter_family(&wrapped_command) != Some(InterpreterFamily::Shell) {
        return None;
    }
    let mut c_body: Option<&str> = None;
    let mut c_requested = false;
    let mut index = 0usize;
    while let Some(arg) = wrapped_command.args.get(index) {
        if *arg == "--" {
            return None; // the input fills a script-file position
        }
        if !arg.starts_with('-') {
            if !c_requested {
                return None; // the input fills the executed script-file slot
            }
            return xargs_sink_kind(landing, c_body, placeholder.as_deref());
        }
        if is_short_option(arg, 'c') {
            c_requested = true;
            c_body = separate_cluster_value(&wrapped_command, index);
        }
        index += 1;
    }
    if c_requested {
        return xargs_sink_kind(landing, c_body, placeholder.as_deref());
    }
    None // no `-c`: the first item becomes the executed script file
}

/// The sink kind for a `-c`-taking wrapped command: a body-less `-c` gives
/// the first item of each invocation batch its own body; a static body
/// takes the input only through a placeholder or positional parameters,
/// and then every item executes.
fn xargs_sink_kind(
    mut landing: XargsLanding,
    c_body: Option<&str>,
    placeholder: Option<&str>,
) -> Option<XargsLanding> {
    match c_body {
        None => Some(landing),
        Some(body) if body_is_input_code(body, placeholder) => {
            landing.sink = XargsSink::PlaceholderCode;
            Some(landing)
        }
        Some(_) => None, // static body: items are positional parameters
    }
}

/// The invocation model of one xargs run: where its input lands in the
/// wrapped command and how the input text is cut into items per
/// invocation.
struct XargsLanding {
    sink: XargsSink,
    items: XargsItems,
}

/// Where the input items go inside the wrapped shell invocation.
enum XargsSink {
    /// A body-less `-c`: the first item of every invocation batch becomes
    /// that invocation's command body.
    BatchBodies,
    /// A `-I` placeholder inside the static `-c` body: every item replaces
    /// it and executes.
    PlaceholderCode,
}

/// How the input text is cut into items, per the option area.
enum XargsItems {
    /// The default: quote-aware whitespace word-splitting over the whole
    /// input; `-n N` runs N items per invocation.
    Word { per_invocation: Option<usize> },
    /// `-I`/`-L`: N logical lines per invocation (a line ending in blanks
    /// continues onto the next). `-I` items are whole logical lines;
    /// `-L` logical lines are still word-split.
    Lines { split: bool, per_invocation: usize },
    /// `-0`/`-d`: no quote processing; the whole input is one item, or is
    /// split on the delimiter; `-n N` still groups the items into
    /// repeated invocations.
    Whole {
        delimiter: Option<String>,
        per_invocation: Option<usize>,
    },
}

impl XargsLanding {
    /// `-n N`: N items per invocation. GNU xargs warns and honors the
    /// LAST of `-I`/`-L`/`-n`: over a line mode word batching replaces it,
    /// while over word/delimiter modes it only retunes the batch size.
    /// Over the `-I` replacement mode, `-n1` specifically changes nothing
    /// (GNU preserves replacement under `-n1`): whole lines stay whole.
    fn set_word_batch(&mut self, count: &str) {
        let Some(n) = xargs_count(count) else {
            return;
        };
        if n == 1
            && matches!(
                self.items,
                XargsItems::Lines {
                    split: false,
                    per_invocation: 1,
                }
            )
        {
            return;
        }
        match &mut self.items {
            XargsItems::Word { per_invocation } | XargsItems::Whole { per_invocation, .. } => {
                *per_invocation = Some(n.max(1));
            }
            XargsItems::Lines { .. } => {
                self.items = XargsItems::Word {
                    per_invocation: Some(n.max(1)),
                };
            }
        }
    }

    /// `-L N`: N logical lines per invocation, each still word-split. The
    /// last of `-I`/`-L`/`-n` wins, so this replaces any earlier mode.
    fn set_line_batch(&mut self, count: &str) {
        let Some(n) = xargs_count(count) else {
            return;
        };
        self.items = XargsItems::Lines {
            split: true,
            per_invocation: n.max(1),
        };
    }

    /// `-0`/`-d`: delimiter-driven item splitting. A `-n` given earlier
    /// keeps grouping the (now delimiter-cut) items.
    fn set_delimited(&mut self, delimiter: Option<String>) {
        let per_invocation = match &self.items {
            XargsItems::Word { per_invocation } | XargsItems::Whole { per_invocation, .. } => {
                *per_invocation
            }
            XargsItems::Lines { .. } => None,
        };
        self.items = XargsItems::Whole {
            delimiter,
            per_invocation,
        };
    }
}

/// One xargs input item: its runtime text and the body line it starts on.
#[derive(Clone)]
struct XargsItem {
    line: usize,
    text: String,
}

/// Logical input lines of the body: a physical line ending in blanks
/// continues onto the next one, so each group is one `-L` line. Blank
/// lines are not counted — GNU `-L` batches NONBLANK lines, so a blank
/// line neither fills a batch nor starts one unless a trailing-blank line
/// logically continues onto it. Each entry keeps its starting physical
/// line.
fn xargs_logical_line_groups(body: &str) -> Vec<Vec<(usize, &str)>> {
    let mut groups: Vec<Vec<(usize, &str)>> = Vec::new();
    for (index, line) in body.lines().enumerate() {
        let continues = groups.last().is_some_and(|group| {
            group
                .last()
                .is_some_and(|(_, text)| text.ends_with([' ', '\t']))
        });
        if line.trim().is_empty() && !continues {
            continue; // a blank line outside a continuation is not counted
        }
        match groups.last_mut() {
            Some(group) if continues => {
                group.push((index, line));
            }
            _ => groups.push(vec![(index, line)]),
        }
    }
    groups
}

/// `-I` items: one whole logical line per item, quote-processed.
fn xargs_line_items(body: &str) -> Vec<XargsItem> {
    xargs_logical_line_groups(body)
        .into_iter()
        .map(|group| {
            let line = group[0].0;
            let merged = group
                .into_iter()
                .map(|(_, text)| text)
                .collect::<Vec<_>>()
                .join(" ");
            XargsItem {
                line,
                text: xargs_strip_item_quotes(&merged),
            }
        })
        .collect()
}

/// xargs input word-splitting: items end at unquoted blanks and newlines;
/// `'…'` is literal, `"…"` honors `\"`/`\\` escapes, and `\c` quotes any
/// character. Each item keeps the body line it starts on.
fn xargs_word_items(body: &str) -> Vec<XargsItem> {
    let mut items = Vec::new();
    let mut item = String::new();
    let mut started = false; // `''` is an item, an unquoted blank run is not
    let mut quote: Option<char> = None;
    let mut line = 0usize;
    let mut characters = body.chars();
    while let Some(character) = characters.next() {
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                } else {
                    item.push(character);
                }
                started = true;
            }
            Some('"') => {
                if character == '"' {
                    quote = None;
                } else if character == '\\' {
                    match characters.next() {
                        Some(escaped @ ('"' | '\\')) => item.push(escaped),
                        Some(other) => {
                            item.push('\\');
                            item.push(other);
                        }
                        None => item.push('\\'),
                    }
                    started = true;
                } else {
                    item.push(character);
                    started = true;
                }
            }
            _ => match character {
                ' ' | '\t' | '\r' => {
                    if started {
                        items.push(XargsItem {
                            line,
                            text: std::mem::take(&mut item),
                        });
                        started = false;
                    }
                }
                '\n' => {
                    if started {
                        items.push(XargsItem {
                            line,
                            text: std::mem::take(&mut item),
                        });
                        started = false;
                    }
                    line += 1;
                }
                '\'' | '"' => {
                    quote = Some(character);
                    started = true;
                }
                '\\' => {
                    started = true;
                    match characters.next() {
                        Some(escaped) => item.push(escaped),
                        None => item.push('\\'),
                    }
                }
                _ => {
                    item.push(character);
                    started = true;
                }
            },
        }
    }
    if started {
        items.push(XargsItem { line, text: item });
    }
    items
}

/// xargs quote processing over one input line (`-I`/`-L` items): quote
/// characters are removed, escapes applied, blanks kept.
fn xargs_strip_item_quotes(line: &str) -> String {
    let mut item = String::new();
    let mut quote: Option<char> = None;
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                } else {
                    item.push(character);
                }
            }
            Some('"') => {
                if character == '"' {
                    quote = None;
                } else if character == '\\' {
                    match characters.next() {
                        Some(escaped @ ('"' | '\\')) => item.push(escaped),
                        Some(other) => {
                            item.push('\\');
                            item.push(other);
                        }
                        None => item.push('\\'),
                    }
                } else {
                    item.push(character);
                }
            }
            _ => match character {
                '\'' | '"' => quote = Some(character),
                '\\' => match characters.next() {
                    Some(escaped) => item.push(escaped),
                    None => item.push('\\'),
                },
                _ => item.push(character),
            },
        }
    }
    item
}

/// Whether a static `-c` body executes xargs input: through positional
/// parameters, or through the `-I` placeholder reaching a code position.
fn body_is_input_code(body: &str, placeholder: Option<&str>) -> bool {
    placeholder.is_some_and(|mark| placeholder_reaches_code(body, mark))
        || positional_parameters_reach_code(body)
}

/// Whether a static operand executes xargs input: only when the `-I`
/// placeholder spells it — a literal script file is repository content.
fn operand_is_input_code(operand: &str, placeholder: Option<&str>) -> bool {
    placeholder.is_some_and(|mark| operand.contains(mark))
}

/// Whether the `-I` placeholder reaches a code position inside a body: a
/// command head, an `eval` argument, or an interpreter's script operand.
/// Data positions (`echo {}`, `cp {} /tmp`) never execute it.
fn placeholder_reaches_code(body: &str, placeholder: &str) -> bool {
    let tokens = tokenize(body);
    conditional_statements(&tokens)
        .iter()
        .any(|(statement, _)| {
            pipeline_segments(statement).iter().any(|segment| {
                let commands = segment_commands(segment);
                let Some(command) = commands.first() else {
                    return false;
                };
                // `command.head` is basename-normalized, which strips leading
                // non-alphanumerics — a placeholder-only head (`{}`, `%x`) must
                // be read from the raw command-position word.
                let mut head_index = 0usize;
                skip_command_prefixes(segment, &mut head_index);
                let raw_head = segment
                    .get(head_index)
                    .and_then(ShellToken::word)
                    .unwrap_or(command.head);
                raw_head.contains(placeholder)
                    || (command.head == "eval"
                        && command.args.iter().any(|arg| arg.contains(placeholder)))
                    || (command_is_interpreter(command)
                        && command
                            .args
                            .first()
                            .is_some_and(|arg| arg.contains(placeholder)))
            })
        })
}

/// Return the actual xargs child-command head after options. Interpreter
/// words in option values or a child command's ordinary argv are data, not
/// evidence that xargs executes shell code.
fn xargs_wrapped_command(command: &ScriptCommand) -> Option<usize> {
    let mut index = 0usize;
    while let Some(arg) = command.args.get(index) {
        if *arg == "--" {
            return (index + 1 < command.args.len()).then_some(index + 1);
        }
        if !arg.starts_with('-') || *arg == "-" {
            return Some(index);
        }
        let long = arg.strip_prefix("--");
        // GNU `--replace[=STR]`, `--max-lines[=N]`, and `--eof[=STR]` take
        // their values only after `=` and never consume the wrapped
        // command; every other valued long option takes a separate value
        // word.
        let takes_value = match long.map(|value| value.split('=').next().unwrap_or(value)) {
            Some("max-args" | "max-procs" | "max-chars" | "delimiter") => !arg.contains('='),
            Some(_) => false,
            None => {
                let short = &arg[1..];
                let valued = short
                    .chars()
                    .next()
                    .is_some_and(|flag| matches!(flag, 'I' | 'n' | 'L' | 'P' | 's' | 'E' | 'd'));
                valued && short.len() == 1
            }
        };
        index += if takes_value { 2 } else { 1 };
    }
    None
}

/// GNU xargs validates its numeric options before reading any input, so a
/// zero or unparsable `-n`/`-L`/`-s` count (or an unparsable `-P` count)
/// makes the whole invocation fail with a usage error and nothing ever
/// executes (`curl URL | xargs -n0 sh -c` reports and exits). Negative
/// counts parse as numbers and fail the same >= 1 check.
fn xargs_option_area_is_valid(command: &ScriptCommand, wrapped: usize) -> bool {
    let mut index = 0usize;
    while index < wrapped {
        let arg = command.args[index];
        let mut advance = 1usize;
        let invalid = if let Some(long) = arg.strip_prefix("--") {
            let (name, glued) = long
                .split_once('=')
                .map(|(name, value)| (name, Some(value)))
                .unwrap_or((long, None));
            match name {
                "max-args" | "max-chars" => {
                    let value = glued.map_or_else(|| command.args.get(index + 1).copied(), Some);
                    if glued.is_none() {
                        advance = 2;
                    }
                    rejects_count(value)
                }
                // GNU `--max-lines[=N]` has an optional argument: the bare
                // form means one line and does not consume the next word.
                "max-lines" => glued.is_some_and(|value| rejects_count(Some(value))),
                // `-P 0` is unlimited parallelism, not a rejection.
                "max-procs" => {
                    let value = glued.map_or_else(|| command.args.get(index + 1).copied(), Some);
                    if glued.is_none() {
                        advance = 2;
                    }
                    value.is_some_and(|value| xargs_count(value).is_none())
                }
                // String-valued options are never invalid, but their
                // separate value word must be consumed.
                "delimiter" => {
                    if glued.is_none() {
                        advance = 2;
                    }
                    false
                }
                _ => false,
            }
        } else if arg.len() > 1 && arg.starts_with('-') {
            let flags = &arg[1..];
            match flags.chars().next() {
                Some(flag @ ('n' | 'L' | 's' | 'P' | 'I' | 'd' | 'E')) => {
                    let value = if flags.len() > 1 {
                        Some(&flags[1..])
                    } else {
                        advance = 2;
                        command.args.get(index + 1).copied()
                    };
                    match flag {
                        'n' | 'L' | 's' => rejects_count(value),
                        // `-P 0` is unlimited parallelism.
                        'P' => value.is_some_and(|value| xargs_count(value).is_none()),
                        _ => false,
                    }
                }
                _ => false,
            }
        } else {
            false
        };
        if invalid {
            return false;
        }
        index += advance;
    }
    true
}

/// GNU rejects a zero or unparsable count for `-n`/`-L`/`-s` ("value 0 for
/// -n option should be >= 1", "invalid number").
fn rejects_count(value: Option<&str>) -> bool {
    value.is_some_and(|value| xargs_count(value).is_none_or(|count| count == 0))
}

/// Positional parameters only taint execution when they flow into command
/// position or an explicit code sink. `echo "$@"` is output data, while
/// `"$@"` and `eval "$@"` execute it.
fn positional_parameters_reach_code(body: &str) -> bool {
    let leading = body.trim_start();
    if (leading.starts_with("$@")
        || leading.starts_with("$*")
        || leading.starts_with("${@")
        || leading.starts_with("${*"))
        && references_positional_parameters(leading)
    {
        return true;
    }
    let tokens = tokenize(body);
    conditional_statements(&tokens)
        .iter()
        .any(|(statement, _)| {
            pipeline_segments(statement).iter().any(|segment| {
                let commands = segment_commands(segment);
                let Some(command) = commands.first() else {
                    return false;
                };
                let head_tainted = references_positional_parameters(command.head);
                let eval_tainted = command.head == "eval"
                    && command
                        .args
                        .iter()
                        .any(|arg| references_positional_parameters(arg));
                head_tainted || eval_tainted
            })
        })
}

/// Whether an argument is a short-option cluster carrying the given flag —
/// `-c` alone or closing a cluster (`-lc`); long options never match.
fn is_short_option(arg: &str, flag: char) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(flag)
}

/// Whether shell text references the positional parameters (`$@`, `$*`,
/// `$0`…`$9`, and their brace forms) — the marks of input words flowing
/// into an executed body.
fn references_positional_parameters(body: &str) -> bool {
    body.contains("$@")
        || body.contains("$*")
        || body.contains("${@")
        || body.contains("${*")
        || body
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'$' && pair[1].is_ascii_digit())
}
