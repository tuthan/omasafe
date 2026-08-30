//! High-signal shell indicators.
//!
//! Extracted from `detect.rs` (plan A4): the reverse-shell spellings and
//! shared-temporary-path predicates the consumption families bind findings
//! to. Indicator predicates never emit findings themselves.
use super::command::{segment_commands, segment_has_redirect_op};
use super::interpreter::INTERPRETER_BASENAMES;
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
