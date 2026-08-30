//! Interpreter and `eval` invocation parsing.
//!
//! Extracted from `detect.rs` (plan A3): interpreter basenames and
//! families, the per-argument execution-mode parse (`-c` bodies, stdin
//! scripts, parse-only, exits), and the statically known shell text a
//! command executes.

use super::command::ScriptCommand;
pub(in crate::detect) fn command_is_interpreter(command: &ScriptCommand) -> bool {
    INTERPRETER_BASENAMES.contains(&command.head)
}

/// What an interpreter invocation executes: stdin as a script, a statically
/// known body (`-c` text), a file or module operand, a parse-only read
/// (`bash -n` checks without executing — the carried body, when the command
/// has one, is what gets parsed instead of stdin), or nothing at all
/// (help/version exits before reading stdin).
pub(in crate::detect) enum InterpreterMode<'a> {
    StdinScript,
    LiteralBody(&'a str),
    FileOrModule,
    ParseOnly { body: Option<&'a str> },
    Exits,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::detect) enum InterpreterFamily {
    Shell,
    Python,
}

pub(in crate::detect) fn interpreter_family(command: &ScriptCommand) -> Option<InterpreterFamily> {
    match command.head {
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" => Some(InterpreterFamily::Shell),
        "python" | "python3" => Some(InterpreterFamily::Python),
        _ => None,
    }
}

/// Parse an interpreter's arguments by token and arity — never by
/// substring — so option payloads never read as modes (`-cecho` is a body,
/// `-O extglob` consumes its value) and mode letters never hide inside
/// unrelated clusters (`--norc` is not `-c`). The FIRST `-c`/`-s`/`-n`
/// selects the execution mode; a `-c` body is glued to the cluster or the
/// next argument, but only when that argument is statically known — a
/// runtime-derived body (`sh -c "$text"`) is outside the static slice.
pub(in crate::detect) fn interpreter_mode<'a>(command: &ScriptCommand<'a>) -> InterpreterMode<'a> {
    if !command_is_interpreter(command) {
        return InterpreterMode::FileOrModule;
    }
    let shell_family = interpreter_family(command) == Some(InterpreterFamily::Shell);
    let mut shell_command_body: Option<&'a str> = None;
    let mut shell_command_requested = false;
    let mut shell_stdin = false;
    let mut shell_noexec = false;
    let mut index = 0usize;
    while let Some(arg) = command.args.get(index) {
        if *arg == "--" {
            // The FIRST operand after `--` selects the script (`-` is
            // stdin); later words are positional parameters, not the script
            // (`sh -- - arg` still reads stdin).
            let operand = command.args[index + 1..]
                .iter()
                .find(|operand| !operand.is_empty())
                .copied();
            // With `-c` pending (its capture deferred to a valued cluster
            // letter), the first operand after `--` is the body.
            if shell_command_body.is_none() && shell_command_requested {
                shell_command_body = operand;
            }
            return if shell_noexec {
                InterpreterMode::ParseOnly {
                    body: shell_command_body,
                }
            } else if let Some(body) = shell_command_body {
                InterpreterMode::LiteralBody(body)
            } else if shell_stdin {
                InterpreterMode::StdinScript
            } else {
                match operand {
                    None | Some("-") => InterpreterMode::StdinScript,
                    Some(_) => InterpreterMode::FileOrModule,
                }
            };
        }
        if *arg == "-" {
            // Conventional stdin operand — unless a pending `-c` takes it as
            // the deferred body (`bash -co errexit -`).
            let body = shell_command_body.or_else(|| shell_command_requested.then_some(*arg));
            return if shell_noexec {
                InterpreterMode::ParseOnly { body }
            } else if let Some(body) = body {
                InterpreterMode::LiteralBody(body)
            } else {
                InterpreterMode::StdinScript
            };
        }
        if let Some(long) = arg.strip_prefix("--") {
            match interpreter_long_option(shell_family, long) {
                LongOption::Exits => return InterpreterMode::Exits,
                LongOption::NoExec => {
                    shell_noexec = true;
                    index += 1;
                }
                LongOption::Flag => index += 1,
                LongOption::Value => {
                    // `--rcfile FILE` — the value is glued on `=` or separate.
                    index += if long.contains('=') { 1 } else { 2 };
                }
            }
            continue;
        }
        if arg.len() > 1 && arg.starts_with(['-', '+']) && shell_family {
            // Shell short clusters accept `+` for the negated `set` form.
            // Parse the complete option area before selecting a mode: `-c`
            // takes the NEXT argv word, `+n` disables noexec, and `-c` wins
            // over `-s` while enabled noexec wins over both.
            let flags = &arg[1..];
            let bytes = flags.as_bytes();
            let mut offset = 0usize;
            let mut advance = 1usize;
            while offset < bytes.len() {
                match bytes[offset] {
                    b'c' => {
                        shell_command_requested = true;
                        // `-c`'s body is the next argv word — but a later
                        // letter of the same cluster may consume it as an
                        // option value first (`-co errexit 'sh'` values
                        // `errexit`, then takes `sh` as the body).
                        let later_valued = bytes[offset + 1..]
                            .iter()
                            .any(|letter| matches!(letter, b'o' | b'O'));
                        if !later_valued {
                            shell_command_body = separate_cluster_value(command, index);
                        }
                        // Remaining bytes are still options, not body text.
                        offset += 1;
                    }
                    b'n' => {
                        shell_noexec = arg.starts_with('-');
                        offset += 1;
                    }
                    b'D' => {
                        shell_noexec = true; // reads/parses stdin without normal execution
                        offset += 1;
                    }
                    b's' => {
                        shell_stdin = true;
                        offset += 1;
                    }
                    b'o' | b'O' => {
                        // valued: glued to the rest of the cluster or the
                        // next argument (`-Oextglob`, `-o errexit`)
                        advance = if offset + 1 < bytes.len() { 1 } else { 2 };
                        break;
                    }
                    _ => offset += 1,
                }
            }
            index += advance;
            continue;
        }
        if arg.len() > 1 && arg.starts_with('-') {
            // Python family, walked the same way: `-c` bodies and `-m`
            // modules replace stdin, `-h`/`-V` exit before reading it, and
            // `-W`/`-X` consume a glued-or-separate value so
            // `-Ximporttime` never reads as module mode.
            let flags = &arg[1..];
            let bytes = flags.as_bytes();
            let mut offset = 0usize;
            let mut advance = 1usize;
            while offset < bytes.len() {
                match bytes[offset] {
                    b'c' => {
                        let glued = &flags[offset + 1..];
                        if glued.is_empty() {
                            return match separate_cluster_value(command, index) {
                                Some(body) => InterpreterMode::LiteralBody(body),
                                None => InterpreterMode::FileOrModule, // dangling or derived
                            };
                        }
                        return InterpreterMode::LiteralBody(glued);
                    }
                    b'm' => return InterpreterMode::FileOrModule, // module mode, not stdin
                    b'h' | b'V' => return InterpreterMode::Exits,
                    b'W' | b'X' => {
                        advance = if offset + 1 < bytes.len() { 1 } else { 2 };
                        break;
                    }
                    _ => offset += 1,
                }
            }
            index += advance;
            continue;
        }
        // First operand: with a pending `-c` whose capture a valued cluster
        // letter deferred, the operand IS the body (`bash -co errexit 'sh'`).
        if shell_command_body.is_none() && shell_command_requested {
            shell_command_body = Some(*arg);
        }
        return if shell_noexec {
            InterpreterMode::ParseOnly {
                body: shell_command_body,
            }
        } else if let Some(body) = shell_command_body {
            InterpreterMode::LiteralBody(body)
        } else if shell_stdin {
            InterpreterMode::StdinScript
        } else {
            InterpreterMode::FileOrModule
        }; // a script file operand
    }
    if shell_noexec {
        InterpreterMode::ParseOnly {
            body: shell_command_body,
        }
    } else if let Some(body) = shell_command_body {
        InterpreterMode::LiteralBody(body)
    } else if shell_stdin || (shell_family && !shell_command_requested) {
        InterpreterMode::StdinScript
    } else if shell_command_requested {
        InterpreterMode::FileOrModule
    } else {
        InterpreterMode::StdinScript // Python without a script also reads stdin
    }
}

/// The next argument as a static option payload (`-c body`): `None` when
/// missing or runtime-derived.
pub(in crate::detect) fn separate_cluster_value<'a>(
    command: &ScriptCommand<'a>,
    index: usize,
) -> Option<&'a str> {
    let next = command.args.get(index + 1)?;
    let dynamic = command.arg_dynamic.get(index + 1).copied().unwrap_or(true);
    (!dynamic).then_some(next)
}

/// How one long option (without its leading `--`) behaves for the
/// interpreter family: some exit without reading stdin at all, some take a
/// separate value, and the rest are plain flags. Unknown options stay
/// flags — an interpreter that rejects one never weakens the
/// executed-stdin reading of the ones it accepts.
enum LongOption {
    Exits,
    /// Implies noexec (`--dump-strings`): input is read and parsed, never
    /// executed — but unlike `--help` it still drains piped stdin.
    NoExec,
    Flag,
    Value,
}

fn interpreter_long_option(shell_family: bool, long: &str) -> LongOption {
    let name = long.split('=').next().unwrap_or(long);
    if shell_family {
        match name {
            "help" | "version" => LongOption::Exits,
            "dump-po-strings" | "dump-strings" => LongOption::NoExec,
            "rcfile" | "init-file" => LongOption::Value,
            _ => LongOption::Flag, // --norc, --noprofile, --posix, …
        }
    } else {
        match name {
            "check" | "help" | "version" => LongOption::Exits,
            _ => LongOption::Flag, // --quiet, --utf8, …
        }
    }
}

/// An interpreter's statically known `-c` body, when it has one: literal
/// text only, since a runtime-derived body (`sh -c "$text"`) resolves
/// outside the static slice.
pub(in crate::detect) fn interpreter_static_body<'a>(
    command: &ScriptCommand<'a>,
) -> Option<&'a str> {
    if interpreter_family(command) != Some(InterpreterFamily::Shell) {
        return None;
    }
    match interpreter_mode(command) {
        InterpreterMode::LiteralBody(body) if !body.is_empty() => Some(body),
        _ => None,
    }
}

/// The statically known shell text a command executes: an interpreter's
/// `-c` body, or an `eval` argument list joined the way eval concatenates
/// its arguments with spaces. Any runtime-derived argument puts the whole
/// text outside the static slice.
pub(in crate::detect) fn static_command_body(command: &ScriptCommand) -> Option<String> {
    if command.head == "eval" {
        if command.args.is_empty() || command.arg_dynamic.iter().any(|dynamic| *dynamic) {
            return None;
        }
        let body = command
            .args
            .iter()
            .skip(usize::from(command.args.first() == Some(&"--")))
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        return (!body.is_empty()).then_some(body);
    }
    interpreter_static_body(command).map(str::to_owned)
}

/// Interpreter basenames that consume piped/substituted content, shared by
/// the pipe, process-substitution, and decode-execute consumers.
pub(in crate::detect) const INTERPRETER_BASENAMES: [&str; 8] = [
    "sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python3",
];
