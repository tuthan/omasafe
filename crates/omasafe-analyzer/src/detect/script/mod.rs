//! Script frontend: shell/Python dispatch and result anchoring, plus the
//! heredoc-ownership and forwarded-body classifiers the shell source layer
//! receives from here.

pub(in crate::detect) mod python;

use self::python::python_reverse_shell;

use crate::detect::model::{
    CommentStyle, FileOutcome, PYTHON_DOWNLOAD_EXECUTE_RULE, PYTHON_PRIVILEGE_RULE,
    PYTHON_REVERSE_SHELL_RULE, SCRIPT_DOWNLOAD_EXECUTE_RULE, SCRIPT_PRIVILEGE_RULE,
    disclose_budget_limitation, find_word, occurrence, parts, strip_line_comment, unquoted_text,
};
use crate::detect::shell::budget::ShellBudget;
use crate::detect::shell::command::{
    ScriptCommand, command_arguments, command_basename, env_split_string_command,
    is_redirect_operator, segment_commands, skip_command_prefixes, skip_wrapper_options,
};
use crate::detect::shell::consumption::shell_consumption_findings;
use crate::detect::shell::effects::{segment_stdin_reaches_interpreter, segment_stdout_preserved};
use crate::detect::shell::egress::{tokens_fetch_egress, unit_has_direct_fetch};
use crate::detect::shell::interpreter::{
    InterpreterFamily, InterpreterMode, interpreter_family, interpreter_mode,
};
use crate::detect::shell::ir::{LogicalUnit, ShellProgram};
use crate::detect::shell::lexer::{ShellToken, tokenize};
use crate::detect::shell::source::shell_logical_units;
use crate::detect::shell::syntax::{conditional_statements, pipeline_segments};
use crate::detect::shell::xargs::xargs_body_fate;
use crate::fingerprint::Confidence;
use crate::payload::PayloadKind;
use crate::rules::{Capability, Language};

/// Minimal high-signal lexical rules for bundled shell/Python payloads.
/// Coverage is always labelled `partial`; no match never implies clean.
/// What a heredoc-owning command does with the redirected body: a shell
/// interpreter in stdin-script mode executes it, a pure stdin-forwarding
/// filter passes it to whatever consumes its stdout downstream, and
/// everything else treats it as data. The command containing the redirect
/// runs from the last top-level separator before it; wrapper chains count
/// when their wrapped command qualifies (`sudo sh <<X` executes the body).
pub(in crate::detect) fn classify_heredoc_owner(
    tokens: &[ShellToken],
    op_index: usize,
) -> crate::detect::shell::source::HeredocOwner {
    use crate::detect::shell::source::HeredocOwner;

    // Classify the command at the redirect's own nesting depth. The source
    // pass inserts `;` for physical newlines inside a group, so a multiline
    // `(\n sh <<C` arrives as `( ; sh <<C`; slicing from the innermost group
    // opener lets the ordinary command parser see `sh` instead of the group
    // punctuation. Separators at that same depth still select the command
    // immediately owning the redirect.
    let mut groups = Vec::new();
    for (index, token) in tokens[..op_index].iter().enumerate() {
        match token.operator() {
            Some("(" | "{" | "((") => groups.push(index),
            Some(")" | "}" | "))") => {
                groups.pop();
            }
            _ => {}
        }
    }
    let start = groups.last().map_or(0, |opener| opener + 1);
    let mut boundary = start;
    let mut depth = 0usize;
    for (index, token) in tokens[start..op_index].iter().enumerate() {
        match token.operator() {
            Some("(" | "{" | "((") => depth += 1,
            Some(")" | "}" | "))") => depth = depth.saturating_sub(1),
            Some("|" | "|&" | ";" | "&&" | "||" | "&") if depth == 0 => {
                boundary = start + index + 1;
            }
            _ => {}
        }
    }
    let commands = segment_commands(&tokens[boundary..op_index]);
    if commands.iter().any(|command| {
        interpreter_family(command) == Some(InterpreterFamily::Shell)
            && matches!(interpreter_mode(command), InterpreterMode::StdinScript)
    }) {
        return HeredocOwner::ExecutesStdin;
    }
    // `tee` always re-emits its stdin on stdout; `cat` only when no file
    // operand replaces the redirected stdin.
    if commands.iter().any(|command| match command.head {
        "tee" => true,
        "cat" => command.args.iter().all(|arg| arg.starts_with('-')),
        _ => false,
    }) {
        return HeredocOwner::ForwardsStdin;
    }
    HeredocOwner::Data
}

/// What becomes of a forwarded heredoc body downstream: the tail is parsed
/// whole and walked stage by stage with the same stdin models the inline
/// pipeline analysis uses — a stage the body reaches either executes it as
/// code, forwards it to the next stage's stdin (a plain transformer with
/// unredirected stdout), or spends it as data. A directly spelled
/// stdin-script shell interpreter yields the byte offset just past its head
/// word, where the body attaches as its `-c` body; an `xargs` sink applies
/// its input model to the body text (quoting, word splitting, replacement);
/// every other executing sink — a static `-c` body consuming stdin
/// (`sh -c sh`), a compound group's interpreter, `source /dev/stdin`,
/// `eval "$(cat)"` — has no direct insertion point and reports
/// `ExecutedIndirectly` so the body's lines stay in the source. Data sinks
/// and downstream modes that never read stdin as a script (`sh -n`,
/// `sh -c body`, `sh script.sh`, `--help`) report `NotExecuted`.
pub(in crate::detect) fn forwarded_body_fate(
    tail: &str,
    body: &str,
) -> crate::detect::shell::source::ForwardedBodyFate {
    use crate::detect::shell::source::ForwardedBodyFate;
    let tokens = tokenize(tail);
    // The tail opens with the pipeline operator that carried the body out
    // of the heredoc owner (`| sh`); the body enters its first stage.
    let downstream = match tokens.split_first() {
        Some((first, rest)) if matches!(first.operator(), Some("|" | "|&")) => rest,
        _ => &tokens[..],
    };
    // Later list members (`| sh; rm …`, `| sh && more`) run with their own
    // stdin; only the first statement carries the body.
    let Some(&(statement, _)) = conditional_statements(downstream).first() else {
        return ForwardedBodyFate::NotExecuted;
    };
    let segments = pipeline_segments(statement);
    let mut budget = ShellBudget::new();
    for (stage, segment) in segments.iter().enumerate() {
        // The stage executes its inherited stdin as code: the sink.
        if segment_stdin_reaches_interpreter(segment, &mut budget) {
            return match sink_head(segment) {
                // The body attaches as the interpreter's `-c` body.
                Some((head_end, command))
                    if interpreter_family(&command) == Some(InterpreterFamily::Shell)
                        && matches!(interpreter_mode(&command), InterpreterMode::StdinScript) =>
                {
                    ForwardedBodyFate::AttachAt(head_end)
                }
                // xargs feeds its input to the wrapped command's argv: its
                // own option, replacement, and input-field model decides
                // which part of the body actually executes.
                Some((_, command)) if command.head == "xargs" => xargs_body_fate(&command, body),
                // Every other executing sink consumes the body verbatim as
                // shell source.
                Some(_) => ForwardedBodyFate::ExecutedIndirectly,
                None => ForwardedBodyFate::ExecutedIndirectly,
            };
        }
        // Anything else keeps the body alive only by passing it through to
        // the next stage; walking off the end leaves it unexecuted.
        if stage + 1 == segments.len() || !segment_stdout_preserved(segment, &mut budget) {
            return ForwardedBodyFate::NotExecuted;
        }
    }
    ForwardedBodyFate::NotExecuted
}

/// The sink stage's command chain, unwrapped through execution and
/// privilege wrappers the way `segment_commands` does, with the final
/// head's byte span and its command (`sudo -u root sh` yields `sh` after
/// its span). `None` when the chain never lands on a word.
fn sink_head(segment: &[ShellToken]) -> Option<(usize, ScriptCommand<'_>)> {
    let mut index = 0usize;
    skip_command_prefixes(segment, &mut index);
    let (head, head_end) = loop {
        let word = segment.get(index).and_then(ShellToken::word)?;
        let basename = command_basename(word);
        let span_end = segment[index].span()?.1;
        if !matches!(
            basename,
            "sudo" | "pkexec" | "doas" | "command" | "env" | "exec" | "time"
        ) {
            break (basename, span_end);
        }
        index += 1;
        // `env -S 'sh …'` word-splits its command string: no position in
        // it can carry a mechanical rewrite.
        if basename == "env" && env_split_string_command(segment, index).is_some() {
            return None;
        }
        if !skip_wrapper_options(basename, segment, &mut index) {
            return None; // options ran off the end: nothing is executed
        }
    };
    // The command's own arguments end at the first non-redirection
    // operator — a statement separator or group closer inside a compound
    // (`(sh; cat)` leaves `cat` to the group, not to `sh`).
    let args_end = segment[index + 1..]
        .iter()
        .position(|token| matches!(token, ShellToken::Operator(op) if !is_redirect_operator(op)))
        .map_or(segment.len(), |offset| index + 1 + offset);
    let arguments = command_arguments(&segment[..args_end], index + 1);
    Some((
        head_end,
        ScriptCommand {
            head,
            args: arguments.iter().map(|(value, _)| *value).collect(),
            arg_dynamic: arguments.iter().map(|(_, dynamic)| *dynamic).collect(),
        },
    ))
}

pub(in crate::detect) fn analyze_script_source(source: &str, kind: PayloadKind) -> FileOutcome {
    let mut outcome = FileOutcome {
        result_parts: Vec::new(),
        capabilities: Vec::new(),
        references: Vec::new(),
        parse_degraded: false,
        confidence: Confidence::LexicalFallback,
        limitations: Vec::new(),
    };
    // Set when the recursion budget for untrusted shell text runs out on any
    // line: the analysis degrades and discloses the shortfall.
    let mut budget_exhausted = false;

    // Shell commands assemble into LOGICAL units across escaped newlines,
    // open pipelines, quotes, and groups (H3 review): `curl URL \` followed
    // by `| sh`, and the grammar continuation `curl URL |` followed by
    // `sh`, are one pipeline, not two fragments. Python keeps its
    // per-line scan; the classic one-liner chains its statements with `;`.
    let units: Vec<(u32, String)> = match kind {
        PayloadKind::Python => source
            .lines()
            .enumerate()
            .map(|(index, raw_line)| {
                (
                    index as u32 + 1,
                    strip_line_comment(raw_line, CommentStyle::PythonHash).to_owned(),
                )
            })
            .filter(|(_, line)| !line.is_empty())
            .collect(),
        _ => shell_logical_units(source, &classify_heredoc_owner, &forwarded_body_fate),
    };

    match kind {
        PayloadKind::Python => {
            for (number, line) in units {
                let line = line.as_str();
                let tokens = tokenize(line);
                analyze_script_unit(
                    number,
                    line,
                    &tokens,
                    &kind,
                    None,
                    &mut outcome,
                    &mut budget_exhausted,
                );
            }
        }
        _ => {
            let program = ShellProgram::from_units(units);
            for unit in program.units() {
                analyze_script_unit(
                    unit.start_line,
                    unit.source(),
                    unit.tokens(),
                    &kind,
                    Some(unit),
                    &mut outcome,
                    &mut budget_exhausted,
                );
            }
        }
    }

    if budget_exhausted {
        disclose_budget_limitation(&mut outcome);
    }

    outcome
}

/// Analyze one already-tokenized unit. Shell callers provide the token stream
/// owned by `ShellProgram`; Python keeps its line-level tokenizer because it
/// is not part of the shell grammar.
fn analyze_script_unit(
    number: u32,
    line: &str,
    tokens: &[ShellToken],
    kind: &PayloadKind,
    shell_unit: Option<&LogicalUnit>,
    outcome: &mut FileOutcome,
    budget_exhausted: &mut bool,
) {
    let language = match kind {
        PayloadKind::Python => Language::Python,
        _ => Language::Shell,
    };
    let (download_rule, privilege_rule) = match kind {
        PayloadKind::Python => (PYTHON_DOWNLOAD_EXECUTE_RULE, PYTHON_PRIVILEGE_RULE),
        _ => (SCRIPT_DOWNLOAD_EXECUTE_RULE, SCRIPT_PRIVILEGE_RULE),
    };

    // Download-and-execute (Python) and reverse-shell wiring are line-level
    // on purpose: the classic Python one-liner chains its statements with
    // `;`, so socket creation, connect, and descriptor handoff legally live
    // in separate statements of one line. Shell consumption families below
    // are statement-scoped instead.
    let code = unquoted_text(line);
    let python_fetch_to_exec = matches!(kind, PayloadKind::Python)
        && (code.contains("urlopen") || code.contains("requests.get") || code.contains("urllib"))
        && (code.contains("os.system")
            || code.contains("subprocess")
            || code.contains("exec(")
            || code.contains("eval("));
    if python_fetch_to_exec {
        outcome.result_parts.push(parts(
            download_rule,
            number,
            "download-execute",
            Confidence::LexicalFallback,
        ));
    }

    // Egress attribution (H3): a fetch tool in command position is network
    // access from the plugin regardless of what happens to the response.
    // Quoted literals stay invisible, while a fetch inside a live command
    // substitution is attributed. The budget bounds substitution and group
    // recursion over untrusted text.
    let mut budget = ShellBudget::new();
    let token_fetch_egress = tokens_fetch_egress(tokens, &mut budget);
    let ir_direct_fetch = shell_unit.is_some_and(|unit| unit_has_direct_fetch(unit, &mut budget));
    if token_fetch_egress || ir_direct_fetch {
        outcome.capabilities.push(occurrence(
            Capability::NetworkAccess,
            language,
            number,
            line.trim(),
        ));
    }
    if budget.exhausted() {
        *budget_exhausted = true;
    }

    // Privilege escalation: an actual passwordless grant or a sudoers WRITE.
    // Read-only inspection and bare sudo/pkexec invocation stay at capability
    // level. Both grant predicates require a real write context.
    let write_indicator = line.contains(">")
        || line.contains(">>")
        || line.contains("tee ")
        || line.contains("visudo")
        || line.contains("sed -i")
        || line.contains("chattr")
        || line.contains(".write(");
    let first_word = line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("");
    let readonly_inspection = matches!(
        first_word,
        "grep" | "cat" | "less" | "head" | "tail" | "stat" | "journalctl"
    );
    let grant_write_context = write_indicator && !readonly_inspection;
    let sudoers_write = line.contains("sudoers") && grant_write_context;
    let nopasswd_grant = line.contains("NOPASSWD") && grant_write_context;
    if nopasswd_grant || sudoers_write {
        outcome.result_parts.push(parts(
            privilege_rule,
            number,
            if nopasswd_grant {
                "passwordless-root"
            } else {
                "sudoers-write"
            },
            Confidence::LexicalFallback,
        ));
    }
    if ["sudo ", "pkexec ", "doas "]
        .iter()
        .any(|token| line.contains(token))
    {
        outcome.capabilities.push(occurrence(
            Capability::ProcessExecution,
            language,
            number,
            line.trim(),
        ));
    }
    if find_word(line, "systemctl").is_some()
        || find_word(line, "systemd-run").is_some()
        || find_word(line, "rc-service").is_some()
    {
        outcome.capabilities.push(occurrence(
            Capability::PersistenceScheduling,
            language,
            number,
            line.trim(),
        ));
    }
    if find_word(line, "pacman").is_some()
        || find_word(line, "paru").is_some()
        || find_word(line, "yay").is_some()
        || find_word(line, "apt-get").is_some()
        || find_word(line, "dnf ").is_some()
    {
        outcome.capabilities.push(occurrence(
            Capability::ProcessExecution,
            language,
            number,
            line.trim(),
        ));
    }

    // Reverse shell (H3, Python): socket and descriptor wiring must be
    // explicit. Multi-line wiring remains the H4 dataflow slice.
    if matches!(kind, PayloadKind::Python) {
        if python_reverse_shell(&code) {
            outcome.result_parts.push(parts(
                PYTHON_REVERSE_SHELL_RULE,
                number,
                "reverse-shell",
                Confidence::LexicalFallback,
            ));
        }
    } else {
        // Shell consumption families are statement- and command-scoped. A
        // fetcher, decoder, or chmod binds only to its own statement and
        // command position; compound groups recurse into their own lists.
        let mut found = Vec::new();
        let mut budget = ShellBudget::new();
        shell_consumption_findings(
            tokens,
            shell_unit,
            number,
            download_rule,
            &mut found,
            &mut budget,
        );
        if budget.exhausted() {
            *budget_exhausted = true;
        }
        outcome.result_parts.extend(found);
    }
}
