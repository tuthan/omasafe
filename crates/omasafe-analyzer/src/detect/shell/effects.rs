//! Shell stdin/stdout/code-execution effects over parsed commands.
//!
//! Extracted from `detect.rs` (plan A4): the stdin/stdout behavior model of
//! pipeline stages and compound groups, live-producer reachability, the
//! xargs input model, and the fetch/decode command classifications the
//! detector families share.

use super::budget::ShellBudget;
use super::command::{
    ScriptCommand, compound_position, depth_zero_redirect_moves_stdin_away,
    depth_zero_redirect_moves_stdout, segment_commands, statement_outcomes,
};
use super::interpreter::{
    InterpreterFamily, InterpreterMode, command_is_interpreter, interpreter_family,
    interpreter_mode, interpreter_static_body, static_command_body,
};
use super::lexer::{ShellToken, SubstKind, tokenize};
use super::syntax::{GroupKind, Outcomes, conditional_statements, pipeline_segments};
use super::xargs::xargs_feeds_stdin_code;

/// What a statically known shell body (an interpreter `-c` body, an `eval`
/// argument) does with its inherited stdin, computed by the same walks that
/// read inline pipelines. Every field fails closed on an exhausted budget.
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
    if !budget.enter() {
        return ShellSummary::SILENT;
    }
    let tokens = tokenize(body);
    let (consumes_stdin_as_code, drains_stdin) = group_stdin_reaches_interpreter(&tokens, budget);
    let forwards_stdin_body = group_forwards_stdin(&tokens, budget);
    budget.leave();
    ShellSummary {
        consumes_stdin_as_code,
        drains_stdin,
        forwards_stdin_body,
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

/// Whether a command in a pipeline segment executes its inherited stdin as
/// shell code: an interpreter in stdin-script mode, an interpreter whose
/// static `-c` body itself consumes stdin as code (`sh -c sh`), or an
/// explicit stdin-to-code consumer (`source /dev/stdin`, `xargs` feeding a
/// body-less interpreter `-c`).
fn command_consumes_stdin_code(command: &ScriptCommand, budget: &mut ShellBudget) -> bool {
    if let Some(body) = interpreter_static_body(command) {
        return static_body_summary(body, budget).consumes_stdin_as_code;
    }
    if interpreter_family(command) == Some(InterpreterFamily::Shell) {
        return matches!(interpreter_mode(command), InterpreterMode::StdinScript);
    }
    stdin_code_consumer(command)
}

/// Explicit stdin-to-code consumers beyond interpreters: `source
/// /dev/stdin` (and the `.` spelling, whose basename is empty) executes the
/// pipe directly, and `xargs` hands its input words to the wrapped command.
fn stdin_code_consumer(command: &ScriptCommand) -> bool {
    if matches!(command.head, "source" | "") {
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

pub(in crate::detect) fn command_fetches(command: &ScriptCommand) -> bool {
    matches!(command.head, "curl" | "wget")
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

/// What a segment's leading command does with data arriving on its stdin.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StdinBehavior {
    /// Reads it and emits it on stdout (`cat`, `sed`): a downstream pipeline
    /// segment receives the data.
    Forwards,
    /// Reads it without handing the body on (`sh` running stdin as script,
    /// `cat >/dev/null`).
    Consumes,
    /// Leaves it untouched for whatever runs next (`echo`, `true`).
    Untouched,
}

/// The leading command's stdin behavior, following compound groups into
/// their statements (the first reading command decides).
fn segment_stdin_behavior(segment: &[ShellToken], budget: &mut ShellBudget) -> StdinBehavior {
    if let Some((kind, group)) = compound_position(segment) {
        if kind != GroupKind::List {
            return StdinBehavior::Untouched; // arithmetic reads no stdin
        }
        if !budget.spend(group.len()) || !budget.enter() {
            return StdinBehavior::Consumes; // unresolved: assume the pipe is spent
        }
        let mut behavior = StdinBehavior::Untouched;
        let mut outcomes = Outcomes::ANY;
        for (statement, guard) in conditional_statements(group) {
            if statement.is_empty() {
                continue;
            }
            if !outcomes.executes(guard) {
                continue;
            }
            if let Some(first) = pipeline_segments(statement).first() {
                behavior = segment_stdin_behavior(first, budget);
                if behavior != StdinBehavior::Untouched {
                    break;
                }
            }
            outcomes = outcomes.advance(guard, statement_outcomes(statement));
        }
        budget.leave();
        return behavior;
    }
    let commands = segment_commands(segment);
    let Some(command) = commands.first() else {
        return StdinBehavior::Untouched;
    };
    if depth_zero_redirect_moves_stdin_away(segment) {
        return StdinBehavior::Untouched; // the pipe is replaced before it
    }
    if let Some(body) = interpreter_static_body(command) {
        let summary = static_body_summary(body, budget);
        return if summary.consumes_stdin_as_code || summary.drains_stdin {
            StdinBehavior::Consumes
        } else if summary.forwards_stdin_body {
            StdinBehavior::Forwards
        } else {
            StdinBehavior::Untouched // the body never reads its stdin
        };
    }
    if command_is_interpreter(command) {
        return match interpreter_mode(command) {
            // A stdin-script interpreter consumes the pipe; so does a
            // parse-only interpreter WITHOUT a body (`bash -n`,
            // `--dump-strings` read and parse stdin, executing nothing).
            // With a `-c` body, the body is what gets parsed and the pipe
            // stays available for what runs next
            // (`bash -n -c 'echo safe'; sh`). Only stdin-script mode is an
            // H3 code sink.
            InterpreterMode::StdinScript | InterpreterMode::ParseOnly { body: None } => {
                StdinBehavior::Consumes
            }
            InterpreterMode::ParseOnly { body: Some(_) }
            | InterpreterMode::FileOrModule
            | InterpreterMode::Exits
            | InterpreterMode::LiteralBody(_) => StdinBehavior::Untouched,
        };
    }
    if !command_is_interpreter(command) && stdin_code_consumer(command) {
        return StdinBehavior::Consumes; // the pipe becomes executed code
    }
    if !drains_stdin(command.head, &command.args) {
        return StdinBehavior::Untouched; // the pipe is never read here
    }
    if depth_zero_redirect_moves_stdout(segment) {
        return StdinBehavior::Consumes; // read, but emitted elsewhere
    }
    if forwards_stdin_body(command) {
        StdinBehavior::Forwards
    } else {
        StdinBehavior::Consumes // the pipe drains into derived output
    }
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
        None => {
            segment_commands(segment)
                .iter()
                .any(|command| command_consumes_stdin_code(command, budget))
                || segment_consumes_stdin_substitution(segment, budget)
        }
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
            let behaviors: Vec<StdinBehavior> = segments
                .iter()
                .map(|segment| segment_stdin_behavior(segment, budget))
                .collect();
            let mut data = pipe_alive;
            for (index, segment) in segments.iter().enumerate() {
                if data {
                    reached |= segment_reaches_interpreter(segment, budget);
                }
                if index + 1 < segments.len() {
                    data &= behaviors[index] == StdinBehavior::Forwards;
                }
            }
            // The group's pipe survives the statement only if its leading
            // command never read it.
            if pipe_alive && behaviors[0] != StdinBehavior::Untouched {
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
            let behaviors: Vec<StdinBehavior> = segments
                .iter()
                .map(|segment| segment_stdin_behavior(segment, budget))
                .collect();
            // The body flows stage to stage only through forwarding
            // commands; walking off the pipeline's end with it still in
            // hand means it left through the compound's stdout.
            let mut data = pipe_alive;
            for behavior in &behaviors {
                if *behavior != StdinBehavior::Forwards {
                    data = false;
                    break;
                }
            }
            if data {
                forwards = true;
            }
            if pipe_alive && behaviors[0] != StdinBehavior::Untouched {
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
    if !budget.enter() {
        return false;
    }
    let found = tokens_live_fetch_stdout(&tokenize(&body), budget);
    budget.leave();
    found
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
        None => segment_stdin_behavior(segment, budget) == StdinBehavior::Forwards,
    }
}
