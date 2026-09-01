//! High-signal shell indicators.
//!
//! Extracted from `detect.rs` (plan A4): the reverse-shell spellings and
//! shared-temporary-path predicates the consumption families bind findings
//! to. Indicator predicates never emit findings themselves.
use super::command::{segment_commands, segment_has_redirect_op};
use super::interpreter::INTERPRETER_BASENAMES;
use super::ir::{CommandNode, Statement, Word};
use super::lexer::ShellToken;
use crate::detect::lower_contains;

/// High-signal interactive-shell spellings bound to command positions in one
/// pipeline segment: `nc`/`ncat`/`netcat` owning an `-e`/`-le` flag, `socat`
/// owning an `exec:` operand, `bash -i` owning a descriptor-duplication
/// redirect (`>&`, the remote-transport wiring — a plain `>` is a local log
/// file), and a `/dev/tcp/` target behind a redirect on an interpreter or
/// `exec` command. Quoted or echoed mentions are prose — the `/dev/tcp/`
/// needle is read from token values, but the command head gates every branch.
pub(in crate::detect) fn reverse_shell_spelling(segment: &[ShellToken]) -> bool {
    let dev_tcp = segment
        .iter()
        .filter_map(ShellToken::word)
        .any(|word| word.contains("/dev/tcp/"));
    let redirect_op = segment_has_redirect_op(segment);
    let dup_redirect = segment.iter().filter_map(ShellToken::operator).any(|op| {
        let digits = op.bytes().take_while(u8::is_ascii_digit).count();
        &op[digits..] == ">&"
    });
    for command in segment_commands(segment) {
        match command.head {
            "nc" | "ncat" | "netcat"
                if command.args.iter().any(|arg| matches!(*arg, "-e" | "-le")) =>
            {
                return true;
            }
            "socat" if command.args.iter().any(|arg| lower_contains(arg, "exec:")) => {
                return true;
            }
            "bash" if command.args.contains(&"-i") && dup_redirect => {
                return true;
            }
            _ => {}
        }
        if dev_tcp
            && redirect_op
            && (INTERPRETER_BASENAMES.contains(&command.head) || command.head == "exec")
        {
            return true;
        }
    }
    false
}

/// Whether any command's own arguments name a shared temporary location.
/// Read from each command's real argument values — redirect operands
/// excluded — so a log target (`sudo /usr/bin/true > /tmp/sudo.log`) never
/// associates a path with a command that never touched one, while a quoted
/// operand (`chmod 777 "/tmp/x"`) still binds.
pub(in crate::detect) fn segment_has_shared_temp_path(segment: &[ShellToken]) -> bool {
    segment_commands(segment).iter().any(|command| {
        command
            .args
            .iter()
            .any(|arg| arg.contains("/tmp/") || arg.contains("/dev/shm"))
    })
}

/// Group/other-writable mode operand for `chmod`: octal with write bits for
/// group or others (`666`, `0777`, `1777`), or a symbolic `+w`/`=w` spelling
/// whose who-list includes group, other, or all (`a+w`, `go+w`, `o=w`).
/// Owner-only grants (`u+w`, `644`, `700`) are not a release.
fn writable_shared_temp_mode(token: &str) -> bool {
    let digits = token.trim_start_matches('0');
    if !digits.is_empty()
        && digits.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
        && let Ok(mode) = u32::from_str_radix(digits, 8)
    {
        return mode & 0o022 != 0;
    }
    for suffix in ["+w", "=w"] {
        if let Some(who) = token.strip_suffix(suffix) {
            return who.is_empty() || who.bytes().any(|byte| matches!(byte, b'a' | b'g' | b'o'));
        }
    }
    false
}

/// A `chmod` command in command position whose own arguments release a
/// group/other-writable mode. The shared-temp path is bound to the same
/// segment by the caller; the connected untrusted-write predicate belongs to
/// the H4 dataflow slice.
pub(in crate::detect) fn chmod_relaxes_shared_temp(segment: &[ShellToken]) -> bool {
    segment_commands(segment).iter().any(|command| {
        command.head == "chmod"
            && command
                .args
                .iter()
                .any(|arg| writable_shared_temp_mode(arg))
    })
}

/// The indicator facts for one typed simple-command site. Compound nodes are
/// visited separately by `ir_visit_indicators`, so facts from two different
/// inner commands cannot accidentally be paired as if they shared a segment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::detect) struct IrIndicatorSummary {
    pub(in crate::detect) reverse_shell: bool,
    pub(in crate::detect) shared_temp_path: bool,
    pub(in crate::detect) privileged_wrapper: bool,
    pub(in crate::detect) chmod_release: bool,
}

/// Visit the same command sites that the legacy indicator predicates saw, but
/// use the typed IR's command heads, arguments, redirects, and reachability.
/// The callback runs once per logical pipeline stage, preserving the scope
/// needed to pair a privileged command or chmod with its own temp-path args.
pub(in crate::detect) fn ir_visit_indicators(
    statements: &[Statement],
    visit: &mut impl FnMut(IrIndicatorSummary),
) {
    for statement in statements
        .iter()
        .filter(|statement| statement.reachable.is_reachable())
    {
        for pipeline in &statement.pipelines {
            for node in &pipeline.commands {
                ir_visit_node(node, visit);
            }
        }
    }
}

fn ir_visit_node(node: &CommandNode, visit: &mut impl FnMut(IrIndicatorSummary)) {
    match node {
        CommandNode::Simple(command) => {
            visit(ir_simple_indicators(command));
            for substitution in &command.head_substitutions {
                if let Some(program) = substitution.program.as_deref() {
                    ir_visit_program(program, visit);
                }
            }
            if let Some(body) = &command.body
                && let Some(program) = body.program.as_deref()
            {
                ir_visit_program(program, visit);
            }
            for word in command
                .wrappers
                .iter()
                .flat_map(|wrapper| wrapper.args.iter())
                .chain(command.args.iter())
            {
                ir_visit_word_substitutions(word, visit);
            }
        }
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            ir_visit_indicators(body, visit)
        }
        CommandNode::Arithmetic { expression, .. } => {
            for word in expression {
                ir_visit_word_substitutions(word, visit);
            }
        }
        CommandNode::If {
            condition,
            then_body,
            elif_branches,
            else_body,
            ..
        } => {
            ir_visit_indicators(condition, visit);
            ir_visit_indicators(then_body, visit);
            for branch in elif_branches {
                ir_visit_indicators(&branch.condition, visit);
                ir_visit_indicators(&branch.body, visit);
            }
            ir_visit_indicators(else_body, visit);
        }
        CommandNode::Loop {
            condition, body, ..
        } => {
            ir_visit_indicators(condition, visit);
            ir_visit_indicators(body, visit);
        }
        CommandNode::For { body, .. } => ir_visit_indicators(body, visit),
        CommandNode::Case { word, branches, .. } => {
            ir_visit_word_substitutions(word, visit);
            for branch in branches {
                ir_visit_indicators(&branch.body, visit);
            }
        }
        CommandNode::Opaque { .. } => {}
    }
}

fn ir_visit_program(program: &super::ir::ShellProgram, visit: &mut impl FnMut(IrIndicatorSummary)) {
    for unit in program.units() {
        ir_visit_indicators(&unit.statements, visit);
    }
}

fn ir_visit_word_substitutions(word: &Word, visit: &mut impl FnMut(IrIndicatorSummary)) {
    for substitution in &word.substitutions {
        if let Some(program) = substitution.program.as_deref() {
            ir_visit_program(program, visit);
        }
    }
}

fn ir_simple_indicators(command: &super::ir::Command) -> IrIndicatorSummary {
    let mut summary = IrIndicatorSummary {
        shared_temp_path: command.args.iter().any(word_has_shared_temp_path)
            || command
                .wrappers
                .iter()
                .flat_map(|wrapper| wrapper.args.iter())
                .any(word_has_shared_temp_path),
        ..IrIndicatorSummary::default()
    };
    let duplicate_redirect = command.redirects.iter().any(|redirect| {
        let digits = redirect
            .operator
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        &redirect.operator[digits..] == ">&"
    });
    let has_redirect = !command.redirects.is_empty();
    let redirect_dev_tcp = command
        .redirects
        .iter()
        .any(|redirect| redirect.target.as_ref().is_some_and(word_has_dev_tcp));

    for (head, args) in command
        .wrappers
        .iter()
        .map(|wrapper| (wrapper.head.as_str(), wrapper.args.as_slice()))
        .chain(std::iter::once((
            command.head.as_str(),
            command.args.as_slice(),
        )))
    {
        summary.shared_temp_path |= args.iter().any(word_has_shared_temp_path);
        summary.privileged_wrapper |= matches!(head, "sudo" | "pkexec" | "doas");
        summary.chmod_release |= head == "chmod"
            && args
                .iter()
                .any(|word| writable_shared_temp_mode(&word.value));

        let dev_tcp =
            head.contains("/dev/tcp/") || args.iter().any(|word| word.value.contains("/dev/tcp/"));
        let reverse = match head {
            "nc" | "ncat" | "netcat" => args
                .iter()
                .any(|word| matches!(word.value.as_str(), "-e" | "-le")),
            "socat" => args.iter().any(|word| lower_contains(&word.value, "exec:")),
            "bash" => args.iter().any(|word| word.value == "-i") && duplicate_redirect,
            _ => false,
        };
        summary.reverse_shell |= reverse
            || ((dev_tcp || redirect_dev_tcp)
                && has_redirect
                && (INTERPRETER_BASENAMES.contains(&head) || head == "exec"));
    }
    summary
}

fn word_has_shared_temp_path(word: &Word) -> bool {
    word.value.contains("/tmp/") || word.value.contains("/dev/shm")
}

fn word_has_dev_tcp(word: &Word) -> bool {
    word.value.contains("/dev/tcp/")
}
