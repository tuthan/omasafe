//! Shell stdin/stdout/code-execution effects over parsed commands.
//!
//! Extracted from `detect.rs` (plan A4): the stdin/stdout behavior model of
//! pipeline stages and compound groups, live-producer reachability, the
//! xargs input model, and the fetch/decode command classifications the
//! detector families share.

use std::sync::Arc;

use super::budget::{CachedStdinSummary, ShellBudget};
use super::command::{
    ScriptCommand, compound_position, depth_zero_redirect_moves_stdin_away,
    depth_zero_redirect_moves_stdout, redirect_moves_stdin_away, redirect_moves_stdout_away,
    segment_commands, statement_outcomes,
};
use super::egress::ir_program_live_fetch_stdout;
use super::interpreter::{
    InterpreterFamily, InterpreterMode, command_is_interpreter, interpreter_family,
    interpreter_mode, static_command_body,
};
use super::ir::{
    Command as IrCommand, CommandNode, ExecutedBody, Redirect as IrRedirect, ShellProgram,
};
use super::lexer::{ShellToken, SubstKind, tokenize};
use super::syntax::{GroupKind, Outcomes, conditional_statements, pipeline_segments};
use super::xargs::xargs_feeds_stdin_code;

/// How a command handles the bytes arriving on its stdin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum StdinEffect {
    Unread,
    Consumed,
    /// The command spends stdin to construct arguments for a code-running
    /// child (`xargs sh -c`); it does not forward the bytes to the next pipe.
    ForwardedExecutableText,
    /// A known transformer emits the input-derived bytes on stdout.
    ForwardedDerivedData,
}

/// What happens to this command's stdout at its own command site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum StdoutEffect {
    Inherited,
    ForwardedInput,
    DerivedData,
    Redirected,
}

/// What code, if any, this command executes from an input or argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum ExecutionEffect {
    None,
    ExecutesStdin,
    ExecutesStaticBody,
    ExecutesTaintedArgument,
}

/// Whether this command directly performs network egress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum EgressEffect {
    None,
    NetworkFetch,
}

/// One command-site effect summary consumed by stdin, stdout, execution, and
/// egress analyses. The summary is deliberately local to a parsed segment;
/// pipeline reachability composes summaries without reclassifying command
/// heads independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) struct CommandEffects {
    pub(in crate::detect) stdin: StdinEffect,
    pub(in crate::detect) stdout: StdoutEffect,
    pub(in crate::detect) execution: ExecutionEffect,
    pub(in crate::detect) egress: EgressEffect,
}

impl CommandEffects {
    const UNREAD: Self = Self {
        stdin: StdinEffect::Unread,
        stdout: StdoutEffect::Inherited,
        execution: ExecutionEffect::None,
        egress: EgressEffect::None,
    };
}

/// What a statically known shell body (an interpreter `-c` body, an `eval`
/// argument) does with its inherited stdin, computed by the same walks that
/// read inline pipelines. Every field fails closed on an exhausted budget.
#[derive(Clone, Copy)]
struct ShellSummary {
    /// The body executes inherited stdin as code (`sh -c sh`).
    consumes_stdin_as_code: bool,
    /// The body spends the inherited pipe without forwarding it
    /// (`sh -c 'cat >/dev/null'`).
    drains_stdin: bool,
    /// The body passes inherited stdin through to its own stdout
    /// (`sh -c 'cat'`).
    forwards_stdin_body: bool,
}

impl ShellSummary {
    const SILENT: Self = Self {
        consumes_stdin_as_code: false,
        drains_stdin: false,
        forwards_stdin_body: false,
    };
}

/// Analyse one static shell body, charging one depth level for the reparse.
fn static_body_summary(body: &str, budget: &mut ShellBudget) -> ShellSummary {
    if budget.exhausted() {
        return ShellSummary::SILENT;
    }
    if let Some(summary) = budget.cached_stdin_summary(body) {
        return ShellSummary {
            consumes_stdin_as_code: summary.consumes_stdin_as_code,
            drains_stdin: summary.drains_stdin,
            forwards_stdin_body: summary.forwards_stdin_body,
        };
    }
    let program = ShellProgram::from_source(body, 0);
    if !program.requires_legacy_fallback() {
        return body_summary_from_ir(
            &ExecutedBody {
                source: body.to_owned(),
                program: Some(Arc::new(program)),
            },
            budget,
        );
    }
    if !budget.enter() {
        return ShellSummary::SILENT;
    }
    let tokens = tokenize(body);
    let (consumes_stdin_as_code, drains_stdin) = group_stdin_reaches_interpreter(&tokens, budget);
    let forwards_stdin_body = group_forwards_stdin(&tokens, budget);
    budget.leave();
    let summary = ShellSummary {
        consumes_stdin_as_code,
        drains_stdin,
        forwards_stdin_body,
    };
    if !budget.exhausted() {
        budget.cache_stdin_summary(
            body,
            CachedStdinSummary {
                consumes_stdin_as_code,
                drains_stdin,
                forwards_stdin_body,
            },
        );
    }
    summary
}

/// Summarize one simple command site. This is the single command-level
/// decision point for stdin, stdout, execution, and direct network effects;
/// compound groups are composed by the recursive segment walks below.
pub(in crate::detect) fn command_effects(
    command: &ScriptCommand,
    segment: &[ShellToken],
    budget: &mut ShellBudget,
) -> CommandEffects {
    command_effects_with_redirects(
        command,
        depth_zero_redirect_moves_stdout(segment),
        depth_zero_redirect_moves_stdin_away(segment),
        budget,
    )
}

/// Apply the same command-site summary to a typed IR command. Redirects,
/// argument provenance, and available static child summaries come from the
/// IR node, so callers do not need to reconstruct a token segment.
pub(in crate::detect) fn ir_command_effects(
    command: &IrCommand,
    budget: &mut ShellBudget,
) -> CommandEffects {
    let stdout_redirected = ir_redirects_move_stdout(&command.redirects);
    let stdin_redirected = ir_redirects_move_stdin(&command.redirects);
    let body = command.body.as_ref();
    let mut effects = with_ir_script_command(command, |script_command| {
        command_effects_with_body_summary(
            script_command,
            stdout_redirected,
            stdin_redirected,
            body,
            budget,
        )
    });
    if !matches!(
        effects.execution,
        ExecutionEffect::ExecutesStdin | ExecutionEffect::ExecutesTaintedArgument
    ) && ir_command_consumes_stdin_substitution(command, budget)
    {
        effects.stdin = StdinEffect::Consumed;
        effects.execution = ExecutionEffect::ExecutesTaintedArgument;
    }
    effects
}

/// Whether a typed command's behavior depends on the stdin it inherits from
/// its parent. This intentionally ignores the command site's own redirects;
/// callers use the answer to compose those redirects with a child summary.
pub(in crate::detect) fn ir_command_depends_on_inherited_stdin(
    command: &IrCommand,
    budget: &mut ShellBudget,
) -> bool {
    with_ir_script_command(command, |script_command| {
        command_effects_with_body_summary(
            script_command,
            false,
            false,
            command.body.as_ref(),
            budget,
        )
        .stdin
            != StdinEffect::Unread
    })
}

fn with_ir_script_command<T>(command: &IrCommand, f: impl FnOnce(&ScriptCommand) -> T) -> T {
    let args: Vec<&str> = command
        .args
        .iter()
        .map(|word| word.value.as_str())
        .collect();
    let arg_dynamic: Vec<bool> = command
        .args
        .iter()
        .map(|word| !word.provenance.is_static())
        .collect();
    let script_command = ScriptCommand {
        head: &command.head,
        args,
        arg_dynamic,
    };
    f(&script_command)
}

fn command_effects_with_redirects(
    command: &ScriptCommand,
    stdout_redirected: bool,
    stdin_redirected: bool,
    budget: &mut ShellBudget,
) -> CommandEffects {
    command_effects_with_body_summary(command, stdout_redirected, stdin_redirected, None, budget)
}

fn command_effects_with_body_summary(
    command: &ScriptCommand,
    stdout_redirected: bool,
    stdin_redirected: bool,
    typed_body: Option<&ExecutedBody>,
    budget: &mut ShellBudget,
) -> CommandEffects {
    let mut effects = CommandEffects {
        stdout: if stdout_redirected {
            StdoutEffect::Redirected
        } else {
            StdoutEffect::Inherited
        },
        egress: direct_egress_effect(command),
        ..CommandEffects::UNREAD
    };

    // A command may still run a static body with redirected stdin, but no
    // inherited pipe bytes can reach it. This early guard prevents a
    // redirected `sh` or `xargs` from becoming a false code sink.
    if stdin_redirected {
        if typed_body.is_some() || static_command_body(command).is_some() {
            effects.execution = ExecutionEffect::ExecutesStaticBody;
        }
        return effects;
    }

    if let Some(body) = typed_body {
        let summary = body_summary_from_ir(body, budget);
        return apply_static_body_effects(effects, summary, stdout_redirected);
    }

    if let Some(body) = static_command_body(command) {
        let summary = static_body_summary(&body, budget);
        return apply_static_body_effects(effects, summary, stdout_redirected);
    }

    if command_is_interpreter(command) {
        match interpreter_mode(command) {
            InterpreterMode::StdinScript => {
                effects.stdin = StdinEffect::Consumed;
                if interpreter_family(command) == Some(InterpreterFamily::Shell) {
                    effects.execution = ExecutionEffect::ExecutesStdin;
                }
            }
            InterpreterMode::ParseOnly { body: None } => {
                effects.stdin = StdinEffect::Consumed;
            }
            InterpreterMode::ParseOnly { body: Some(_) }
            | InterpreterMode::LiteralBody(_)
            | InterpreterMode::FileOrModule
            | InterpreterMode::Exits => {}
        }
        return effects;
    }

    if stdin_code_consumer(command) {
        effects.stdin = if command.head == "xargs" {
            StdinEffect::ForwardedExecutableText
        } else {
            StdinEffect::Consumed
        };
        effects.execution = if command.head == "xargs" {
            ExecutionEffect::ExecutesTaintedArgument
        } else {
            ExecutionEffect::ExecutesStdin
        };
        return effects;
    }

    if !drains_stdin(command.head, &command.args) {
        return effects;
    }
    if stdout_redirected {
        effects.stdin = StdinEffect::Consumed;
    } else if forwards_stdin_body(command) {
        effects.stdin = StdinEffect::ForwardedDerivedData;
        effects.stdout = StdoutEffect::ForwardedInput;
    } else {
        effects.stdin = StdinEffect::Consumed;
        effects.stdout = StdoutEffect::DerivedData;
    }
    effects
}

fn apply_static_body_effects(
    mut effects: CommandEffects,
    summary: ShellSummary,
    stdout_redirected: bool,
) -> CommandEffects {
    effects.execution = if summary.consumes_stdin_as_code {
        ExecutionEffect::ExecutesStdin
    } else {
        ExecutionEffect::ExecutesStaticBody
    };
    if summary.consumes_stdin_as_code || summary.drains_stdin {
        effects.stdin = StdinEffect::Consumed;
    } else if summary.forwards_stdin_body {
        effects.stdin = StdinEffect::ForwardedDerivedData;
        if !stdout_redirected {
            effects.stdout = StdoutEffect::ForwardedInput;
        }
    }
    effects
}

/// Summarize a parsed child program without tokenizing its source again.
/// The outer `enter` accounts for the executed body; compound helpers charge
/// their own typed statement work and nested recursion below that boundary.
fn body_summary_from_ir(body: &ExecutedBody, budget: &mut ShellBudget) -> ShellSummary {
    if budget.exhausted() {
        return ShellSummary::SILENT;
    }
    if let Some(summary) = budget.cached_stdin_summary(&body.source) {
        return ShellSummary {
            consumes_stdin_as_code: summary.consumes_stdin_as_code,
            drains_stdin: summary.drains_stdin,
            forwards_stdin_body: summary.forwards_stdin_body,
        };
    }
    let Some(program) = body.program.as_deref() else {
        return static_body_summary(&body.source, budget);
    };
    if !budget.enter() {
        return ShellSummary::SILENT;
    }
    let mut consumes_stdin_as_code = false;
    let mut drains_stdin = false;
    let mut forwards_stdin_body = false;
    for unit in program.units() {
        let (consumes, drains) = ir_group_stdin_reaches_interpreter(&unit.statements, budget);
        consumes_stdin_as_code |= consumes;
        drains_stdin |= drains;
        forwards_stdin_body |= ir_group_forwards_stdin(&unit.statements, budget);
    }
    budget.leave();
    let summary = ShellSummary {
        consumes_stdin_as_code,
        drains_stdin,
        forwards_stdin_body,
    };
    if !budget.exhausted() {
        budget.cache_stdin_summary(
            &body.source,
            CachedStdinSummary {
                consumes_stdin_as_code,
                drains_stdin,
                forwards_stdin_body,
            },
        );
    }
    summary
}

fn ir_command_consumes_stdin_substitution(command: &IrCommand, budget: &mut ShellBudget) -> bool {
    let eval = command.head == "eval";
    command.args.iter().any(|word| {
        word.substitutions.iter().any(|substitution| {
            if substitution.kind != SubstKind::Command {
                return false;
            }
            let Some(program) = substitution.program.as_ref() else {
                return false;
            };
            let body = ExecutedBody {
                source: substitution.source.clone(),
                program: Some(Arc::clone(program)),
            };
            let summary = body_summary_from_ir(&body, budget);
            summary.consumes_stdin_as_code || (eval && summary.forwards_stdin_body)
        })
    })
}

fn ir_redirects_move_stdout(redirects: &[IrRedirect]) -> bool {
    redirects.iter().any(|redirect| {
        redirect_moves_stdout_away(
            &redirect.operator,
            redirect
                .target
                .as_ref()
                .map_or("", |target| target.value.as_str()),
        )
    })
}

fn ir_redirects_move_stdin(redirects: &[IrRedirect]) -> bool {
    redirects.iter().any(|redirect| {
        redirect_moves_stdin_away(
            &redirect.operator,
            redirect
                .target
                .as_ref()
                .map_or("", |target| target.value.as_str()),
        )
    })
}

fn direct_egress_effect(command: &ScriptCommand) -> EgressEffect {
    if matches!(command.head, "curl" | "wget") {
        EgressEffect::NetworkFetch
    } else {
        EgressEffect::None
    }
}

/// Whether any executed statement's pipeline carries a live fetch producer
/// whose output reaches the pipeline's end — the body's or span's stdout
/// (`sh -c 'curl URL'` produces the response; `sh -c 'curl URL | sh'`
/// produces only the inner script's output).
pub(in crate::detect) fn tokens_live_fetch_stdout(
    tokens: &[ShellToken],
    budget: &mut ShellBudget,
) -> bool {
    if !budget.spend(tokens.len()) {
        return false;
    }
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(tokens) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue;
        }
        if pipeline_has_live_producer(&pipeline_segments(statement), budget, &command_fetches) {
            return true;
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    false
}

/// Explicit stdin-to-code consumers beyond interpreters: `source
/// /dev/stdin` (and the `.` spelling) executes the
/// pipe directly, and `xargs` hands its input words to the wrapped command.
fn stdin_code_consumer(command: &ScriptCommand) -> bool {
    if matches!(command.head, "source" | ".") {
        return command
            .args
            .first()
            .is_some_and(|operand| matches!(*operand, "/dev/stdin" | "/dev/fd/0"));
    }
    if command.head == "xargs" {
        return xargs_feeds_stdin_code(command);
    }
    false
}

/// Whether the segment's own words carry a command substitution that turns
/// the inherited pipe into executed code: any head runs a substitution
/// whose interior itself executes stdin as code (`echo "$(sh)"`), and an
/// `eval` head additionally executes a substitution that merely forwards
/// the pipe to its output (`eval "$(cat)"`).
fn segment_consumes_stdin_substitution(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let head_eval = segment_commands(segment)
        .iter()
        .any(|command| command.head == "eval");
    let mut depth = 0i32;
    for token in segment {
        match token {
            ShellToken::Operator(op) => match op.as_str() {
                "(" | "{" | "((" => depth += 1,
                ")" | "}" | "))" => depth = (depth - 1).max(0),
                _ => {}
            },
            ShellToken::Word { substitutions, .. } if depth == 0 => {
                for substitution in substitutions {
                    if substitution.kind != SubstKind::Command {
                        continue;
                    }
                    if !budget.enter() {
                        return false;
                    }
                    let tokens = tokenize(&substitution.inner);
                    let (consumes, _) = group_stdin_reaches_interpreter(&tokens, budget);
                    let forwards = group_forwards_stdin(&tokens, budget);
                    budget.leave();
                    if consumes || (head_eval && forwards) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Summarize a non-compound pipeline segment, including command substitutions
/// that turn inherited stdin into executed text (`eval "$(cat)"`). Wrapper
/// chains are represented by their final command for stdin/stdout semantics;
/// the command-level summary still retains direct egress for that command.
fn simple_segment_effects(segment: &[ShellToken], budget: &mut ShellBudget) -> CommandEffects {
    let commands = segment_commands(segment);
    let Some(command) = commands.last() else {
        return CommandEffects::UNREAD;
    };
    let mut effects = command_effects(command, segment, budget);
    if !matches!(
        effects.execution,
        ExecutionEffect::ExecutesStdin | ExecutionEffect::ExecutesTaintedArgument
    ) && segment_consumes_stdin_substitution(segment, budget)
    {
        effects.stdin = StdinEffect::Consumed;
        effects.execution = ExecutionEffect::ExecutesTaintedArgument;
    }
    effects
}

pub(in crate::detect) fn command_fetches(command: &ScriptCommand) -> bool {
    direct_egress_effect(command) == EgressEffect::NetworkFetch
}

/// A decoder able to release executable bytes in command position:
/// `base64 -d/--decode`, `openssl enc|base64 … -d`, or `xxd -r`. Flags are
/// token-exact so `-depth` and `-daemon` never satisfy `-d`.
pub(in crate::detect) fn command_decodes(command: &ScriptCommand) -> bool {
    match command.head {
        "base64" | "base32" => command_is_decode_mode(command),
        "openssl" => {
            command
                .args
                .iter()
                .any(|arg| matches!(*arg, "enc" | "base64" | "-base64"))
                && command.args.contains(&"-d")
        }
        "xxd" => command.args.contains(&"-r"),
        _ => false,
    }
}

/// Apply the decoder classifier to a typed command node without rebuilding
/// command position or losing word provenance.
pub(in crate::detect) fn ir_command_decodes(command: &IrCommand) -> bool {
    with_ir_script_command(command, command_decodes)
}

/// Decoder mode shared by finding production and stdin forwarding. GNU
/// base64/base32 decode with `-d`/`--decode`, and `-w` consumes the rest of
/// its cluster (or the next argument) as the wrap width — so `-w0d` is a
/// width whose `d` is value text, never a decode flag, while `-di` decodes.
fn command_is_decode_mode(command: &ScriptCommand) -> bool {
    if !matches!(command.head, "base64" | "base32") {
        return false;
    }
    let mut index = 0usize;
    while let Some(arg) = command.args.get(index) {
        if *arg == "--decode" {
            return true;
        }
        if let Some(flags) = arg
            .strip_prefix('-')
            .filter(|flags| !flags.starts_with('-'))
        {
            let mut decode = false;
            for letter in flags.chars() {
                match letter {
                    'd' => decode = true,
                    'w' => break, // everything glued after `-w` is the width
                    _ => {}
                }
            }
            if decode {
                return true;
            }
            // A `-w` cluster with nothing glued takes the next argument.
            if flags.ends_with('w') {
                index += 1;
            }
        }
        index += 1;
    }
    false
}

/// Command heads that read their stdin to exhaustion when it is a pipe:
/// whatever the statement runs after one of these finds the body already
/// consumed (`curl URL | (cat >/dev/null; sh)` leaves `sh` at EOF).
const STDIN_DRAINING_HEADS: [&str; 30] = [
    "cat",
    "grep",
    "egrep",
    "fgrep",
    "sed",
    "awk",
    "sort",
    "uniq",
    "wc",
    "tr",
    "tac",
    "rev",
    "cut",
    "paste",
    "tee",
    "xargs",
    "jq",
    "od",
    "base64",
    "base32",
    "zcat",
    "gzip",
    "gunzip",
    "xxd",
    "cksum",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "strings",
];

/// Whether the command reads its piped stdin to exhaustion: a known stdin
/// filter with no file operands redirecting the read elsewhere, no
/// early-exit mode, and no stdin redirection of its own.
fn drains_stdin(head: &str, args: &[&str]) -> bool {
    match head {
        // These consume the pipe whatever else they are told (tee also
        // forwards it; xargs spends it on child argv; tr only takes sets).
        "tee" | "xargs" | "tr" => return true,
        // `openssl enc|base64 …` reads stdin for encode and decode alike;
        // `-in FILE` takes the read elsewhere (`-pass pass:…` values are
        // options, not files), and `dd` reads it fully unless a count or
        // an `if=` input file limits or replaces it.
        "openssl" => {
            return (args.contains(&"enc")
                || args.contains(&"base64")
                || args.contains(&"-base64"))
                && !args.contains(&"-in");
        }
        "dd" => {
            return args.iter().all(|arg| arg.contains('='))
                && !args
                    .iter()
                    .any(|arg| arg.starts_with("if=") || arg.starts_with("count="));
        }
        _ if !STDIN_DRAINING_HEADS.contains(&head) => return false,
        _ => {}
    }
    if matches!(head, "grep" | "egrep" | "fgrep")
        && args
            .iter()
            .any(|arg| *arg == "-m" || arg.starts_with("--max-count"))
    {
        return false; // exits after the match count, leaving the pipe unread
    }
    if args.contains(&"--") {
        return false; // everything after `--` is a file operand
    }
    // Count operands with option arity: GNU base64/base32 take no file
    // operands in this model, and their `-w`/`--wrap` width VALUE is option
    // payload, not a file (`base64 -w 0 -d` still drains).
    let skips_value =
        |arg: &&str| matches!(head, "base64" | "base32") && matches!(*arg, "-w" | "--wrap");
    let mut value_expected = false;
    let operands = args
        .iter()
        .filter(|arg| {
            let is_option_value = value_expected;
            value_expected = skips_value(arg);
            !is_option_value && !arg.starts_with('-')
        })
        .count();
    // sed/awk/grep/jq take a program/pattern argument before any file; one
    // such operand leaves stdin attached, more mean a file input.
    let program_arguments = match head {
        "sed" | "awk" | "grep" | "egrep" | "fgrep" | "jq" => 1,
        _ => 0,
    };
    operands <= program_arguments
}

/// Which draining commands still emit what they read (transformed) on
/// stdout, so the piped BODY reaches the next stage — decided per command
/// MODE, parallel to `command_decodes`: `base64`/`base32` forward only
/// while DECODING (`-d`/`--decode`), `xxd` only reversing (`-r`), `gzip`
/// only decompressing, `openssl` only its decode forms — encoding and
/// compressing spend the pipe on derived bytes. The rest of the known
/// transformers pass the body on in every mode, while drainers like
/// `xargs`, `wc`, and the checksum family emit DERIVED output — counts,
/// digests, child argv — and the body stops there.
fn forwards_stdin_body(command: &ScriptCommand) -> bool {
    let args = &command.args;
    match command.head {
        "cat" | "sed" | "awk" | "grep" | "egrep" | "fgrep" | "sort" | "uniq" | "tr" | "tac"
        | "rev" | "cut" | "tee" | "jq" | "zcat" | "gunzip" => true,
        "base64" | "base32" => command_is_decode_mode(command),
        "xxd" => args.contains(&"-r"),
        "gzip" => {
            short_cluster_flag(args, 'd')
                || args
                    .iter()
                    .any(|arg| matches!(*arg, "--decompress" | "--uncompress"))
        }
        "openssl" => {
            (args.contains(&"enc") || args.contains(&"base64") || args.contains(&"-base64"))
                && args.contains(&"-d")
                && !args.contains(&"-in")
        }
        // `dd` copies the body verbatim only as a plain (status-quiet)
        // copier: every argument is a KEY=VALUE option and none redirects
        // the input/output or changes the bytes.
        "dd" => {
            args.iter().all(|arg| arg.contains('='))
                && args.iter().all(|arg| {
                    !arg.starts_with("if=")
                        && !arg.starts_with("of=")
                        && !arg.starts_with("conv=")
                        && !arg.starts_with("skip=")
                        && !arg.starts_with("count=")
                        && !arg.starts_with("ibs=")
                        && !arg.starts_with("obs=")
                })
        }
        _ => false,
    }
}

/// Whether any short-option cluster (single `-`, not `--`) carries the
/// flag letter (`gzip -dc`, `-df`).
fn short_cluster_flag(args: &[&str], flag: char) -> bool {
    args.iter().any(|arg| {
        arg.len() > 1 && arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(flag)
    })
}

/// The segment's stdin effect, following compound groups into their
/// statements (the first command that reads the inherited pipe decides).
fn segment_stdin_effect(segment: &[ShellToken], budget: &mut ShellBudget) -> StdinEffect {
    if let Some((kind, group)) = compound_position(segment) {
        if kind != GroupKind::List {
            return StdinEffect::Unread; // arithmetic reads no stdin
        }
        if !budget.spend(group.len()) || !budget.enter() {
            return StdinEffect::Consumed; // unresolved: assume the pipe is spent
        }
        let mut effect = StdinEffect::Unread;
        let mut outcomes = Outcomes::ANY;
        for (statement, guard) in conditional_statements(group) {
            if statement.is_empty() {
                continue;
            }
            if !outcomes.executes(guard) {
                continue;
            }
            if let Some(first) = pipeline_segments(statement).first() {
                effect = segment_stdin_effect(first, budget);
                if effect != StdinEffect::Unread {
                    break;
                }
            }
            outcomes = outcomes.advance(guard, statement_outcomes(statement));
        }
        budget.leave();
        return effect;
    }
    simple_segment_effects(segment, budget).stdin
}

/// Whether the piped data reaches an interpreter when this segment runs:
/// a plain command inherits the pipe, a compound group's statements run in
/// order under the stdin model. A consumer counts when it will actually
/// execute stdin as code — a stdin-script interpreter, an interpreter
/// whose static `-c` body consumes it (`sh -c sh`), an explicit
/// stdin-to-code consumer (`source /dev/stdin`, `xargs sh -c`), or a
/// substitution that turns the pipe into executed text (`eval "$(cat)"`).
fn segment_reaches_interpreter(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    match compound_position(segment) {
        Some((GroupKind::List, group)) => group_stdin_reaches_interpreter(group, budget).0,
        Some((GroupKind::Arithmetic, _)) => false,
        None => matches!(
            simple_segment_effects(segment, budget).execution,
            ExecutionEffect::ExecutesStdin | ExecutionEffect::ExecutesTaintedArgument
        ),
    }
}

/// Tracks the piped body through a compound consumer group's statements:
/// returns whether an interpreter received it, and whether the group
/// exhausted the pipe for whoever runs after it (`(cat | sh)` both feeds
/// its interpreter and empties the pipe; `(echo x; sh)` leaves nothing for
/// later statements but only because sh ran them). Conditional lists keep
/// their short-circuit semantics: `false && cat >/dev/null` never runs, so
/// the body survives for the next statement.
fn group_stdin_reaches_interpreter(group: &[ShellToken], budget: &mut ShellBudget) -> (bool, bool) {
    if !budget.spend(group.len()) || !budget.enter() {
        return (false, false);
    }
    let mut pipe_alive = true;
    let mut reached = false;
    let mut drained = false;
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(group) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue; // short-circuited: the pipe is untouched by it
        }
        let segments = pipeline_segments(statement);
        if !segments.is_empty() {
            let effects: Vec<StdinEffect> = segments
                .iter()
                .map(|segment| segment_stdin_effect(segment, budget))
                .collect();
            let mut data = pipe_alive;
            for (index, segment) in segments.iter().enumerate() {
                if data {
                    reached |= segment_reaches_interpreter(segment, budget);
                }
                if index + 1 < segments.len() {
                    data &= effects[index] == StdinEffect::ForwardedDerivedData;
                }
            }
            // The group's pipe survives the statement only if its leading
            // command never read it.
            if pipe_alive
                && effects[0] != StdinEffect::Unread
                && !depth_zero_redirect_moves_stdin_away(segments[0])
            {
                pipe_alive = false;
                drained = true;
            }
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    budget.leave();
    (reached, drained)
}

/// Whether a compound INTERMEDIATE pipeline stage passes the piped body
/// through to its stdout: some statement must read the live pipe and emit
/// it unredirected (`(cat)` forwards, `(cat >/dev/null)` and `(sh)` spend
/// it, `(echo x)` never touches it and the body stops there).
fn group_forwards_stdin(group: &[ShellToken], budget: &mut ShellBudget) -> bool {
    if !budget.spend(group.len()) || !budget.enter() {
        return false;
    }
    let mut pipe_alive = true;
    let mut forwards = false;
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(group) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue;
        }
        let segments = pipeline_segments(statement);
        if !segments.is_empty() {
            let effects: Vec<StdinEffect> = segments
                .iter()
                .map(|segment| segment_stdin_effect(segment, budget))
                .collect();
            // The body flows stage to stage only through forwarding
            // commands; walking off the pipeline's end with it still in
            // hand means it left through the compound's stdout.
            let mut data = pipe_alive;
            for effect in &effects {
                if *effect != StdinEffect::ForwardedDerivedData {
                    data = false;
                    break;
                }
            }
            if data {
                forwards = true;
            }
            if pipe_alive
                && effects[0] != StdinEffect::Unread
                && !depth_zero_redirect_moves_stdin_away(segments[0])
            {
                pipe_alive = false;
            }
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
        if forwards {
            break;
        }
    }
    budget.leave();
    forwards
}

/// The typed equivalent of `segment_stdin_effect`: a command node's own
/// redirects are applied before walking a compound body's first reachable
/// pipeline stage. This is the command-site effect used by typed consumer
/// reachability; token walks remain responsible for re-parsed child text.
pub(in crate::detect) fn ir_node_stdin_effect(
    node: &CommandNode,
    budget: &mut ShellBudget,
) -> StdinEffect {
    let redirects = match node {
        CommandNode::Simple(command) => &command.redirects,
        CommandNode::Subshell { redirects, .. }
        | CommandNode::BraceGroup { redirects, .. }
        | CommandNode::Arithmetic { redirects, .. }
        | CommandNode::If { redirects, .. }
        | CommandNode::Loop { redirects, .. }
        | CommandNode::For { redirects, .. }
        | CommandNode::Case { redirects, .. }
        | CommandNode::Opaque { redirects, .. } => redirects,
    };
    if ir_redirects_move_stdin(redirects) {
        return StdinEffect::Consumed;
    }
    match node {
        CommandNode::Simple(command) => ir_command_effects(command, budget).stdin,
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            ir_group_stdin_effect(body, budget)
        }
        CommandNode::Arithmetic { .. } | CommandNode::Opaque { .. } => StdinEffect::Unread,
        CommandNode::If {
            condition,
            then_body,
            elif_branches,
            else_body,
            ..
        } => control_stdin_effect(
            condition,
            then_body,
            elif_branches
                .iter()
                .flat_map(|branch| branch.body.iter())
                .chain(else_body.iter()),
            budget,
        ),
        CommandNode::Loop {
            condition, body, ..
        } => control_stdin_effect(condition, body, std::iter::empty(), budget),
        CommandNode::For { body, .. } => {
            control_stdin_effect(&[], body, std::iter::empty(), budget)
        }
        CommandNode::Case { branches, .. } => control_stdin_effect(
            &[],
            &[],
            branches.iter().flat_map(|branch| branch.body.iter()),
            budget,
        ),
    }
}

fn control_stdin_effect<'a>(
    condition: &[super::ir::Statement],
    body: &[super::ir::Statement],
    extra: impl Iterator<Item = &'a super::ir::Statement>,
    budget: &mut ShellBudget,
) -> StdinEffect {
    for statements in [condition, body] {
        let effect = ir_group_stdin_effect(statements, budget);
        if effect != StdinEffect::Unread {
            return effect;
        }
    }
    for statement in extra {
        let effect = ir_group_stdin_effect(std::slice::from_ref(statement), budget);
        if effect != StdinEffect::Unread {
            return effect;
        }
    }
    StdinEffect::Unread
}

fn control_reaches_interpreter(
    condition: &[super::ir::Statement],
    then_body: &[super::ir::Statement],
    elif_branches: &[super::ir::Branch],
    else_body: &[super::ir::Statement],
    budget: &mut ShellBudget,
) -> bool {
    statements_reach_interpreter(condition, budget)
        || statements_reach_interpreter(then_body, budget)
        || elif_branches.iter().any(|branch| {
            statements_reach_interpreter(&branch.condition, budget)
                || statements_reach_interpreter(&branch.body, budget)
        })
        || statements_reach_interpreter(else_body, budget)
}

fn statements_reach_interpreter(
    statements: &[super::ir::Statement],
    budget: &mut ShellBudget,
) -> bool {
    statements
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
        .any(|statement| {
            statement.pipelines.iter().any(|pipeline| {
                pipeline
                    .commands
                    .iter()
                    .any(|node| ir_node_reaches_interpreter(node, budget))
            })
        })
}

fn control_forwards_stdin(
    then_body: &[super::ir::Statement],
    elif_branches: &[super::ir::Branch],
    else_body: &[super::ir::Statement],
    budget: &mut ShellBudget,
) -> bool {
    statements_forward_stdin(then_body, budget)
        || elif_branches
            .iter()
            .any(|branch| statements_forward_stdin(&branch.body, budget))
        || statements_forward_stdin(else_body, budget)
}

fn statements_forward_stdin(statements: &[super::ir::Statement], budget: &mut ShellBudget) -> bool {
    statements
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
        .any(|statement| {
            statement.pipelines.iter().any(|pipeline| {
                !pipeline.commands.is_empty()
                    && pipeline.commands.iter().all(|node| {
                        ir_node_stdin_effect(node, budget) == StdinEffect::ForwardedDerivedData
                    })
            })
        })
}

fn node_redirects_stdin(node: &CommandNode) -> bool {
    let redirects = match node {
        CommandNode::Simple(command) => &command.redirects,
        CommandNode::Subshell { redirects, .. }
        | CommandNode::BraceGroup { redirects, .. }
        | CommandNode::Arithmetic { redirects, .. }
        | CommandNode::If { redirects, .. }
        | CommandNode::Loop { redirects, .. }
        | CommandNode::For { redirects, .. }
        | CommandNode::Case { redirects, .. }
        | CommandNode::Opaque { redirects, .. } => redirects,
    };
    ir_redirects_move_stdin(redirects)
}

fn ir_group_stdin_effect(body: &[super::ir::Statement], budget: &mut ShellBudget) -> StdinEffect {
    if !budget.spend(ir_body_work(body)) || !budget.enter() {
        return StdinEffect::Consumed;
    }
    let effect = body
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
        .filter_map(|statement| statement.pipelines.first())
        .filter_map(|pipeline| pipeline.commands.first())
        .map(|node| ir_node_stdin_effect(node, budget))
        .find(|effect| *effect != StdinEffect::Unread)
        .unwrap_or(StdinEffect::Unread);
    budget.leave();
    effect
}

/// Whether a typed command node executes inherited stdin as code. Compound
/// groups use the same short-circuit and pipeline dataflow model as the token
/// path, but read reachability and command effects directly from the IR.
pub(in crate::detect) fn ir_node_reaches_interpreter(
    node: &CommandNode,
    budget: &mut ShellBudget,
) -> bool {
    let redirects = match node {
        CommandNode::Simple(command) => &command.redirects,
        CommandNode::Subshell { redirects, .. }
        | CommandNode::BraceGroup { redirects, .. }
        | CommandNode::Arithmetic { redirects, .. }
        | CommandNode::If { redirects, .. }
        | CommandNode::Loop { redirects, .. }
        | CommandNode::For { redirects, .. }
        | CommandNode::Case { redirects, .. }
        | CommandNode::Opaque { redirects, .. } => redirects,
    };
    if ir_redirects_move_stdin(redirects) {
        return false;
    }
    match node {
        CommandNode::Simple(command) => matches!(
            ir_command_effects(command, budget).execution,
            ExecutionEffect::ExecutesStdin | ExecutionEffect::ExecutesTaintedArgument
        ),
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            ir_group_reaches_interpreter(body, budget)
        }
        CommandNode::Arithmetic { .. } | CommandNode::Opaque { .. } => false,
        CommandNode::If {
            condition,
            then_body,
            elif_branches,
            else_body,
            ..
        } => control_reaches_interpreter(condition, then_body, elif_branches, else_body, budget),
        CommandNode::Loop {
            condition, body, ..
        } => {
            statements_reach_interpreter(condition, budget)
                || statements_reach_interpreter(body, budget)
        }
        CommandNode::For { body, .. } => statements_reach_interpreter(body, budget),
        CommandNode::Case { branches, .. } => branches
            .iter()
            .any(|branch| statements_reach_interpreter(&branch.body, budget)),
    }
}

fn ir_group_reaches_interpreter(body: &[super::ir::Statement], budget: &mut ShellBudget) -> bool {
    ir_group_stdin_reaches_interpreter(body, budget).0
}

fn ir_group_stdin_reaches_interpreter(
    body: &[super::ir::Statement],
    budget: &mut ShellBudget,
) -> (bool, bool) {
    if !budget.spend(ir_body_work(body)) || !budget.enter() {
        return (false, false);
    }
    let mut pipe_alive = true;
    let mut reached = false;
    let mut drained = false;
    for statement in body
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
    {
        for pipeline in &statement.pipelines {
            if pipeline.commands.is_empty() {
                continue;
            }
            let effects: Vec<StdinEffect> = pipeline
                .commands
                .iter()
                .map(|node| ir_node_stdin_effect(node, budget))
                .collect();
            let mut data = pipe_alive;
            for (index, node) in pipeline.commands.iter().enumerate() {
                if data {
                    reached |= ir_node_reaches_interpreter(node, budget);
                }
                if index + 1 < pipeline.commands.len() {
                    data &= effects[index] == StdinEffect::ForwardedDerivedData;
                }
            }
            if pipe_alive
                && effects[0] != StdinEffect::Unread
                && !node_redirects_stdin(&pipeline.commands[0])
            {
                pipe_alive = false;
                drained = true;
            }
        }
    }
    budget.leave();
    (reached, drained)
}

fn ir_group_forwards_stdin(body: &[super::ir::Statement], budget: &mut ShellBudget) -> bool {
    if !budget.spend(ir_body_work(body)) || !budget.enter() {
        return false;
    }
    let mut pipe_alive = true;
    let mut forwards = false;
    for statement in body
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
    {
        for pipeline in &statement.pipelines {
            if pipeline.commands.is_empty() {
                continue;
            }
            let effects: Vec<StdinEffect> = pipeline
                .commands
                .iter()
                .map(|node| ir_node_stdin_effect(node, budget))
                .collect();
            if pipe_alive
                && effects
                    .iter()
                    .all(|effect| *effect == StdinEffect::ForwardedDerivedData)
            {
                forwards = true;
            }
            if pipe_alive
                && effects[0] != StdinEffect::Unread
                && !node_redirects_stdin(&pipeline.commands[0])
            {
                pipe_alive = false;
            }
        }
        if forwards {
            break;
        }
    }
    budget.leave();
    forwards
}

/// Whether a typed intermediate node forwards inherited stdin to its stdout.
/// This lets a typed producer/consumer walk keep redirect ownership on the
/// node instead of asking the token layer to rediscover it.
pub(in crate::detect) fn ir_node_stdout_preserved(
    node: &CommandNode,
    budget: &mut ShellBudget,
) -> bool {
    let redirects = match node {
        CommandNode::Simple(command) => &command.redirects,
        CommandNode::Subshell { redirects, .. }
        | CommandNode::BraceGroup { redirects, .. }
        | CommandNode::Arithmetic { redirects, .. }
        | CommandNode::If { redirects, .. }
        | CommandNode::Loop { redirects, .. }
        | CommandNode::For { redirects, .. }
        | CommandNode::Case { redirects, .. }
        | CommandNode::Opaque { redirects, .. } => redirects,
    };
    if ir_redirects_move_stdout(redirects) {
        return false;
    }
    match node {
        CommandNode::Simple(command) => {
            ir_command_effects(command, budget).stdout == StdoutEffect::ForwardedInput
        }
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            ir_group_forwards_stdin(body, budget)
        }
        CommandNode::Arithmetic { .. } | CommandNode::Opaque { .. } => false,
        CommandNode::If {
            then_body,
            elif_branches,
            else_body,
            ..
        } => control_forwards_stdin(then_body, elif_branches, else_body, budget),
        CommandNode::Loop { body, .. } | CommandNode::For { body, .. } => {
            statements_forward_stdin(body, budget)
        }
        CommandNode::Case { branches, .. } => branches
            .iter()
            .any(|branch| statements_forward_stdin(&branch.body, budget)),
    }
}

/// Charge a bounded amount for one typed body without recharging descendants;
/// nested groups charge themselves when their node is visited.
fn ir_body_work(body: &[super::ir::Statement]) -> usize {
    body.iter()
        .map(|statement| {
            1 + statement
                .pipelines
                .iter()
                .map(|pipeline| 1 + pipeline.commands.len())
                .sum::<usize>()
        })
        .sum()
}

/// Whether the pipeline's stdin still reaches an interpreter when the
/// consumer segment runs. The compound's own stdin redirection (`( … ) <
/// /dev/null`) starves everything inside; otherwise the consumer is walked
/// with the stdin model, so a preceding `cat` that drains the body keeps
/// `curl URL | (cat >/dev/null; sh)` silent while `(echo x; sh)` and
/// `(cat | sh)` still fire.
pub(in crate::detect) fn segment_stdin_reaches_interpreter(
    segment: &[ShellToken],
    budget: &mut ShellBudget,
) -> bool {
    if depth_zero_redirect_moves_stdin_away(segment) {
        return false;
    }
    segment_reaches_interpreter(segment, budget)
}

/// Whether stdout still reaches `consumer` from `producer` along the
/// pipeline: the producer's OWN stdout is judged per command site
/// (segment_has_live_producer); every segment BETWEEN the two must pass the
/// body through.
pub(in crate::detect) fn stdout_reaches(
    segments: &[&[ShellToken]],
    producer: usize,
    consumer: usize,
    budget: &mut ShellBudget,
) -> bool {
    segments[producer + 1..consumer]
        .iter()
        .all(|segment| segment_stdout_preserved(segment, budget))
}

/// Whether the segment holds a fetch/decoder command whose stdout still
/// lands on the shared fd 1 — the pipe — provenance tracked PER COMMAND
/// rather than one compound-wide boolean: a compound's depth-zero redirect
/// starves every site inside it (`( … ) > body`), each inner command's own
/// redirect starves only that command (`(curl URL >/tmp/body; echo safe)`
/// emits nothing from the fetch, while `(curl URL; echo safe >/tmp/log)`
/// already wrote the body into the pipe), short-circuited statements
/// own no live sites at all, and a site's own pipeline must carry its
/// output to the compound's stdout (`(curl URL | cat >/dev/null)`)
/// contributes nothing.
pub(in crate::detect) fn segment_has_live_producer(
    segment: &[ShellToken],
    budget: &mut ShellBudget,
    pred: &impl Fn(&ScriptCommand) -> bool,
) -> bool {
    if depth_zero_redirect_moves_stdout(segment) {
        return false;
    }
    match compound_position(segment) {
        Some((GroupKind::List, group)) => {
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
                if pipeline_has_live_producer(&pipeline_segments(statement), budget, pred) {
                    found = true;
                    break;
                }
                outcomes = outcomes.advance(guard, statement_outcomes(statement));
            }
            budget.leave();
            found
        }
        // Arithmetic evaluates; it emits no command output.
        Some((GroupKind::Arithmetic, _)) => false,
        None => segment_commands(segment)
            .iter()
            .any(|command| pred(command) || command_body_produces_fetch_output(command, budget)),
    }
}

/// Whether a command's statically known body produces fetch output on its
/// own stdout — `sh -c 'curl URL' | sh` runs the response downstream,
/// while `sh -c 'curl URL | sh'` leaves only the inner script's output.
fn command_body_produces_fetch_output(command: &ScriptCommand, budget: &mut ShellBudget) -> bool {
    let Some(body) = static_command_body(command) else {
        return false;
    };
    body_live_fetch_stdout(&body, budget)
}

/// Whether a static shell body emits a live fetch response on its own
/// stdout. The result is cached separately from stdin effects because the
/// two summaries answer different reachability questions.
pub(in crate::detect) fn body_live_fetch_stdout(body: &str, budget: &mut ShellBudget) -> bool {
    if budget.exhausted() {
        return false;
    }
    if let Some(reaches_stdout) = budget.cached_live_fetch_stdout(body) {
        return reaches_stdout;
    }
    if !budget.enter() {
        return false;
    }
    let program = ShellProgram::from_source(body, 0);
    let reaches_stdout = if program.requires_legacy_fallback() {
        tokens_live_fetch_stdout(&tokenize(body), budget)
    } else {
        ir_program_live_fetch_stdout(&program, budget)
    };
    budget.leave();
    if !budget.exhausted() {
        budget.cache_live_fetch_stdout(body, reaches_stdout);
    }
    reaches_stdout
}

/// Whether any pipeline segment is a live producer whose stdout also flows
/// through the REST of its own pipeline — the boundary between the site and
/// the enclosing context (a compound's stdout, or a substitution's
/// collected output): `(curl URL | cat >/dev/null)` and
/// `eval "$(curl URL | cat >/dev/null)"` contribute nothing because `cat`
/// spends the body before the pipeline ends.
pub(in crate::detect) fn pipeline_has_live_producer(
    segments: &[&[ShellToken]],
    budget: &mut ShellBudget,
    pred: &impl Fn(&ScriptCommand) -> bool,
) -> bool {
    segments.iter().enumerate().any(|(site, segment)| {
        segment_has_live_producer(segment, budget, pred)
            && stdout_reaches(segments, site, segments.len(), budget)
    })
}

/// Whether an INTERMEDIATE pipeline segment passes the piped body through
/// to the next one. Plain stages forward only when their leading command is
/// a KNOWN stdin transformer (`cat`, `sed`, `xxd -r`) — `echo safe` and
/// every other non-reading command leave the pipe untouched, so the body
/// stops there. A compound forwards only when one of its statements reads
/// the live pipe and emits it unredirected.
pub(in crate::detect) fn segment_stdout_preserved(
    segment: &[ShellToken],
    budget: &mut ShellBudget,
) -> bool {
    if depth_zero_redirect_moves_stdout(segment) {
        return false;
    }
    match compound_position(segment) {
        Some((GroupKind::List, group)) => group_forwards_stdin(group, budget),
        // Arithmetic never reads its stdin: the body stops there.
        Some((GroupKind::Arithmetic, _)) => false,
        // A plain stage forwards only when its leading command is a KNOWN
        // stdin transformer (the same model that reads compound interiors):
        // `echo safe` leaves the pipe untouched, `cat >/dev/null` spends it,
        // and only a forwarding filter passes the body on.
        None => simple_segment_effects(segment, budget).stdout == StdoutEffect::ForwardedInput,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effects_for(source: &str) -> CommandEffects {
        let tokens = tokenize(source);
        let segment = pipeline_segments(&tokens)
            .first()
            .copied()
            .expect("test source should contain a pipeline segment");
        let commands = segment_commands(segment);
        let command = commands
            .last()
            .expect("test source should contain a command");
        let mut budget = ShellBudget::new();
        command_effects(command, segment, &mut budget)
    }

    #[test]
    fn command_effects_cover_stdin_modes_and_execution() {
        let cases = [
            (
                "sh",
                StdinEffect::Consumed,
                StdoutEffect::Inherited,
                ExecutionEffect::ExecutesStdin,
                EgressEffect::None,
            ),
            (
                "sh -c 'echo safe'",
                StdinEffect::Unread,
                StdoutEffect::Inherited,
                ExecutionEffect::ExecutesStaticBody,
                EgressEffect::None,
            ),
            (
                "sh -n",
                StdinEffect::Consumed,
                StdoutEffect::Inherited,
                ExecutionEffect::None,
                EgressEffect::None,
            ),
            (
                "python3 -W ignore",
                StdinEffect::Consumed,
                StdoutEffect::Inherited,
                ExecutionEffect::None,
                EgressEffect::None,
            ),
            (
                "cat",
                StdinEffect::ForwardedDerivedData,
                StdoutEffect::ForwardedInput,
                ExecutionEffect::None,
                EgressEffect::None,
            ),
            (
                "cat >out",
                StdinEffect::Consumed,
                StdoutEffect::Redirected,
                ExecutionEffect::None,
                EgressEffect::None,
            ),
            (
                "xargs sh -c",
                StdinEffect::ForwardedExecutableText,
                StdoutEffect::Inherited,
                ExecutionEffect::ExecutesTaintedArgument,
                EgressEffect::None,
            ),
            (
                "curl https://example.test/x",
                StdinEffect::Unread,
                StdoutEffect::Inherited,
                ExecutionEffect::None,
                EgressEffect::NetworkFetch,
            ),
            (
                "base64 -d",
                StdinEffect::ForwardedDerivedData,
                StdoutEffect::ForwardedInput,
                ExecutionEffect::None,
                EgressEffect::None,
            ),
        ];

        for (source, stdin, stdout, execution, egress) in cases {
            let effects = effects_for(source);
            assert_eq!(effects.stdin, stdin, "stdin effect for {source:?}");
            assert_eq!(effects.stdout, stdout, "stdout effect for {source:?}");
            assert_eq!(
                effects.execution, execution,
                "execution effect for {source:?}"
            );
            assert_eq!(effects.egress, egress, "egress effect for {source:?}");
        }
    }

    #[test]
    fn static_body_summaries_are_reused_within_one_budget() {
        let mut budget = ShellBudget::new();
        let first = static_body_summary("cat", &mut budget);
        let nodes_after_first = budget.nodes;
        let second = static_body_summary("cat", &mut budget);

        assert_eq!(
            (
                first.consumes_stdin_as_code,
                first.drains_stdin,
                first.forwards_stdin_body,
            ),
            (
                second.consumes_stdin_as_code,
                second.drains_stdin,
                second.forwards_stdin_body,
            )
        );
        assert_eq!(budget.nodes, nodes_after_first);
        assert!(!budget.exhausted());

        assert!(!budget.spend(usize::MAX));
        let exhausted = static_body_summary("cat", &mut budget);
        assert!(!exhausted.consumes_stdin_as_code);
        assert!(!exhausted.drains_stdin);
        assert!(!exhausted.forwards_stdin_body);
    }

    #[test]
    fn live_fetch_summaries_are_reused_independently() {
        let mut budget = ShellBudget::new();
        let first = body_live_fetch_stdout("curl https://example.test/x", &mut budget);
        let nodes_after_first = budget.nodes;
        let second = body_live_fetch_stdout("curl https://example.test/x", &mut budget);

        assert!(first);
        assert_eq!(second, first);
        assert_eq!(budget.nodes, nodes_after_first);
        assert!(!budget.exhausted());
    }

    #[test]
    fn typed_ir_command_effects_keep_redirect_and_provenance_ownership() {
        use crate::detect::shell::ir::{CommandNode, ShellProgram, WordProvenance};

        let program = ShellProgram::from_units(vec![(
            1,
            "sudo sh -c sh; eval \"$BODY\"; cat >out\n".to_owned(),
        )]);
        let unit = &program.units()[0];

        let CommandNode::Simple(wrapped) = &unit.statements[0].pipelines[0].commands[0] else {
            panic!("expected wrapped simple command");
        };
        let mut budget = ShellBudget::new();
        let wrapped_effects = ir_command_effects(wrapped, &mut budget);
        assert_eq!(wrapped_effects.stdin, StdinEffect::Consumed);
        assert_eq!(wrapped_effects.execution, ExecutionEffect::ExecutesStdin);

        let CommandNode::Simple(dynamic) = &unit.statements[1].pipelines[0].commands[0] else {
            panic!("expected dynamic simple command");
        };
        assert_eq!(dynamic.args[0].provenance, WordProvenance::PARAMETER);
        let dynamic_effects = ir_command_effects(dynamic, &mut budget);
        assert_eq!(dynamic_effects.execution, ExecutionEffect::None);
        assert_eq!(dynamic_effects.stdin, StdinEffect::Unread);

        let CommandNode::Simple(redirected) = &unit.statements[2].pipelines[0].commands[0] else {
            panic!("expected redirected simple command");
        };
        let redirected_effects = ir_command_effects(redirected, &mut budget);
        assert_eq!(redirected_effects.stdin, StdinEffect::Consumed);
        assert_eq!(redirected_effects.stdout, StdoutEffect::Redirected);
    }
}
